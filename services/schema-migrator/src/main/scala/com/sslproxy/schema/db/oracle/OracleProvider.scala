package com.sslproxy.schema.db.oracle

import cats.effect.{IO, Resource}
import cats.syntax.all.*
import com.sslproxy.schema.config.MigratorConfig
import com.sslproxy.schema.db.{DbProvider, DbSession, JdbcConnectionConfig, JdbcSupport}
import com.sslproxy.schema.db.syntax.SqlDialect
import com.sslproxy.schema.engine.*
import com.sslproxy.schema.error.MigratorError
import com.sslproxy.schema.validation.RollbackValidator

import java.nio.file.{Files, Path}
import java.sql.{Connection, ResultSet, SQLException}

final class OracleProvider(config: JdbcConnectionConfig) extends DbProvider:
  override val dialect: SqlDialect = SqlDialect.Oracle

  override def session: Resource[IO, DbSession] =
    JdbcSupport.connection(config).map(OracleSession(_))

final class OracleSession(connection: Connection) extends DbSession:
  import JdbcSupport.*

  override def checkConnection: IO[Unit] =
    IO.blocking(queryOne(connection, "select 1 from dual")(_.getInt(1))).void

  override def bootstrap: IO[Unit] =
    IO.blocking {
      OracleSession.bootstrapBlocks.foreach(OracleDdlHelper.executeSql(connection, _))
    }.adaptError {
      case error: SQLException => MigratorError.Apply(s"Oracle schema_control bootstrap failed: ${error.getMessage}", error)
    }

  override def acquireLock: IO[Unit] =
    IO.blocking {
      try
        executePrepared(
          connection,
          """
          insert into schema_control.migration_locks (lock_name, locked_at, locked_by)
          values ('schema_migrate', systimestamp, ?)
          """
        )(_.setString(1, appliedBy))
      catch
        case error: SQLException if error.getErrorCode == 1 =>
          throw MigratorError.Apply("Oracle schema apply lock schema_migrate is already held", error)
    }

  override def releaseLock: IO[Unit] =
    IO.blocking {
      executePrepared(connection, "delete from schema_control.migration_locks where lock_name = 'schema_migrate'")(_ => ())
    }

  override def prepare(objects: List[SchemaObject]): IO[List[PreparedObject]] =
    objects.traverse(prepareOne)

  private def prepareOne(objectDef: SchemaObject): IO[PreparedObject] =
    IO.blocking {
      val existing = queryPrepared(
        connection,
        """
        select content_sha256, apply_status
          from schema_control.schema_objects
         where kind = ? and object_name = ?
        """
      ) { statement =>
        statement.setString(1, objectDef.kind)
        statement.setString(2, objectDef.objectName)
      } { row =>
        row.getString("content_sha256") -> row.getString("apply_status")
      }.headOption

      val oldSha = existing.map(_._1)
      val oldStatus = existing.map(_._2)
      val needsApply = !oldSha.exists(_ == objectDef.sha256) || !oldStatus.exists(Set("applied", "skipped"))
      val status = if needsApply then "pending" else "skipped"

      executePrepared(connection, OracleSession.prepareSql) { statement =>
        statement.setString(1, objectDef.kind)
        statement.setString(2, objectDef.objectName)
        statement.setString(3, objectDef.sourceFile)
        statement.setString(4, objectDef.dependsOn.mkString(","))
        objectDef.rollbackFile.fold(statement.setNull(5, java.sql.Types.VARCHAR))(statement.setString(5, _))
        statement.setString(6, objectDef.canonicalSql)
        statement.setString(7, objectDef.sha256)
        statement.setString(8, status)
      }

      PreparedObject(objectDef, oldSha, needsApply)
    }.adaptError { case error: SQLException =>
      MigratorError.Apply(
        s"failed to prepare Oracle schema control state for ${objectDef.kind}:${objectDef.objectName}: ${error.getMessage}",
        error
      )
    }

  override def recordSkipped(prepared: PreparedObject): IO[Unit] =
    IO.blocking(insertApplyLog(prepared.objectDef, "skipped", prepared.oldSha256, None, None))

  override def executeObject(prepared: PreparedObject): IO[Unit] =
    IO.blocking {
      val started = System.nanoTime()
      try
        OracleDdlHelper.executeSql(connection, prepared.objectDef.rawSql)
        try recordAppliedUnsafe(prepared, durationMs(started))
        catch
          case error: SQLException =>
            throw MigratorError.NonRetryableApply(
              s"${prepared.objectDef.sourceFile}: applied Oracle SQL but failed to record migration state: ${error.getMessage}",
              error
            )
      catch
        case error: SQLException =>
          val formatted = sqlError(prepared.objectDef.sourceFile, error, "oracle")
          recordFailedUnsafe(prepared, formatted, durationMs(started))
          throw MigratorError.Apply(formatted, error)
    }

  override def rollbackObject(sqlDir: Path, objectName: String): IO[Unit] =
    IO.blocking {
      val target = fetchRollbackTargetUnsafe(objectName)
      val pseudoFile = com.sslproxy.schema.discovery.SqlFile(target.kind, sqlDir.resolve(target.sourceFile), target.sourceFile)
      val rollbackPath = RollbackValidator.resolveExistingRollbackPath(pseudoFile, target.rollbackFile).getOrElse {
        throw MigratorError.Apply(s"${target.objectName} declares rollback file '${target.rollbackFile}' but it was not found")
      }
      val rollbackSql = Files.readString(rollbackPath)
      if rollbackSql.trim.isEmpty then throw MigratorError.Apply(s"$rollbackPath: rollback SQL file is empty")
      val started = System.nanoTime()
      try
        OracleDdlHelper.executeSql(connection, rollbackSql)
        executePrepared(
          connection,
          """
          update schema_control.schema_objects
             set apply_status = 'pending',
                 applied_at = null,
                 last_error = null,
                 updated_at = systimestamp
           where kind = ? and object_name = ?
          """
        ) { statement =>
          statement.setString(1, target.kind)
          statement.setString(2, target.objectName)
        }
        insertRollbackLog(target, durationMs(started))
      catch
        case error: SQLException => throw MigratorError.Apply(sqlError(rollbackPath.toString, error, "oracle"), error)
    }

  override def fetchStatus: IO[List[ObjectStatus]] =
    IO.blocking {
      queryList(
        connection,
        """
        select kind, object_name, source_file, apply_status,
               content_sha256,
               to_char(applied_at, 'YYYY-MM-DD HH24:MI:SS') as applied_at,
               dbms_lob.substr(last_error, 4000, 1) as last_error
          from schema_control.schema_objects
         order by kind, object_name
        """
      )(readObjectStatus)
    }

  override def fetchReady: IO[SchemaReadyStatus] =
    IO.blocking {
      queryOne(
        connection,
        """
        select total_count, pending_count, failed_count, applied_count, ready,
               failed_objects,
               to_char(last_updated_at, 'YYYY-MM-DD HH24:MI:SS') as last_updated_at,
               to_char(last_applied_at, 'YYYY-MM-DD HH24:MI:SS') as last_applied_at
          from schema_control.schema_ready
        """
      )(readReadyStatus).getOrElse(SchemaReadyStatus(0, 0, 0, 0, ready = false, Nil, None, None))
    }

  override def checkReady: IO[Boolean] =
    fetchReady.map(_.ready)

  private def recordAppliedUnsafe(prepared: PreparedObject, durationMs: Int): Unit =
    executePrepared(
      connection,
      """
      update schema_control.schema_objects
         set apply_status = 'applied',
             applied_at = systimestamp,
             last_error = null,
             updated_at = systimestamp
       where kind = ? and object_name = ?
      """
    ) { statement =>
      statement.setString(1, prepared.objectDef.kind)
      statement.setString(2, prepared.objectDef.objectName)
    }
    insertApplyLog(prepared.objectDef, "applied", prepared.oldSha256, Some(durationMs), None)

  private def recordFailedUnsafe(prepared: PreparedObject, errorText: String, durationMs: Int): Unit =
    executePrepared(
      connection,
      """
      update schema_control.schema_objects
         set apply_status = 'failed',
             last_error = ?,
             updated_at = systimestamp
       where kind = ? and object_name = ?
      """
    ) { statement =>
      statement.setString(1, errorText)
      statement.setString(2, prepared.objectDef.kind)
      statement.setString(3, prepared.objectDef.objectName)
    }
    insertApplyLog(prepared.objectDef, "failed", prepared.oldSha256, Some(durationMs), Some(errorText))

  private def insertApplyLog(
      objectDef: SchemaObject,
      action: String,
      oldSha: Option[String],
      durationMs: Option[Int],
      errorText: Option[String]
  ): Unit =
    executePrepared(connection, OracleSession.applyLogSql) { statement =>
      statement.setString(1, objectDef.kind)
      statement.setString(2, objectDef.objectName)
      statement.setString(3, objectDef.sourceFile)
      statement.setString(4, action)
      oldSha.fold(statement.setNull(5, java.sql.Types.VARCHAR))(statement.setString(5, _))
      statement.setString(6, objectDef.sha256)
      durationMs.fold(statement.setNull(7, java.sql.Types.INTEGER))(statement.setInt(7, _))
      errorText.fold(statement.setNull(8, java.sql.Types.CLOB))(statement.setString(8, _))
      statement.setString(9, appliedBy)
    }

  private def insertRollbackLog(target: RollbackTarget, durationMs: Int): Unit =
    executePrepared(connection, OracleSession.applyLogSql) { statement =>
      statement.setString(1, target.kind)
      statement.setString(2, target.objectName)
      statement.setString(3, target.sourceFile)
      statement.setString(4, "rolled_back")
      statement.setString(5, target.contentSha256)
      statement.setString(6, target.contentSha256)
      statement.setInt(7, durationMs)
      statement.setNull(8, java.sql.Types.CLOB)
      statement.setString(9, appliedBy)
    }

  private def fetchRollbackTargetUnsafe(objectName: String): RollbackTarget =
    val rows = queryPrepared(
      connection,
      """
      select kind, object_name, source_file, content_sha256, rollback_file
        from schema_control.schema_objects
       where object_name = ?
       order by kind, object_name
      """
    )(_.setString(1, objectName)) { row =>
      Option(row.getString("rollback_file")).map { rollbackFile =>
        RollbackTarget(
          kind = row.getString("kind"),
          objectName = row.getString("object_name"),
          sourceFile = row.getString("source_file"),
          contentSha256 = row.getString("content_sha256"),
          rollbackFile = rollbackFile
        )
      }
    }.flatten

    rows match
      case Nil => throw MigratorError.Apply(s"no tracked schema object named $objectName")
      case target :: Nil => target
      case many =>
        val matches = many.map(target => s"${target.kind}:$objectName").mkString(", ")
        throw MigratorError.Apply(s"object name $objectName is ambiguous; matches: $matches")

  private def readObjectStatus(row: ResultSet): ObjectStatus =
    ObjectStatus(
      kind = row.getString("kind"),
      objectName = row.getString("object_name"),
      sourceFile = row.getString("source_file"),
      applyStatus = row.getString("apply_status"),
      contentSha256 = row.getString("content_sha256"),
      appliedAt = Option(row.getString("applied_at")),
      lastError = Option(row.getString("last_error"))
    )

  private def readReadyStatus(row: ResultSet): SchemaReadyStatus =
    SchemaReadyStatus(
      totalCount = row.getLong("total_count"),
      pendingCount = row.getLong("pending_count"),
      failedCount = row.getLong("failed_count"),
      appliedCount = row.getLong("applied_count"),
      ready = row.getString("ready") == "1",
      failedObjects = Option(row.getString("failed_objects")).toList.flatMap(_.split(',').map(_.trim).filter(_.nonEmpty)),
      lastUpdatedAt = Option(row.getString("last_updated_at")),
      lastAppliedAt = Option(row.getString("last_applied_at"))
    )

  private def appliedBy: String =
    s"${sys.env.getOrElse("HOSTNAME", "unknown-host")}:${ProcessHandle.current().pid()}"

object OracleProvider:
  def fromConfig(config: MigratorConfig): IO[OracleProvider] =
    for
      password <- config.oraclePasswordFile.traverse(JdbcSupport.readPasswordFile)
      provider <- IO.fromEither {
        configureWallet(config)
        val jdbcUrl = config.databaseUrl
          .orElse(sys.env.get("ORACLE_JDBC_URL"))
          .orElse(config.oracleTnsAlias.map(alias => s"jdbc:oracle:thin:@$alias"))
          .toRight("ORACLE_JDBC_URL or --oracle-tns-alias is required for Oracle")

        jdbcUrl.map { url =>
          OracleProvider(
            JdbcConnectionConfig(
              driver = "oracle.jdbc.OracleDriver",
              url = url,
              user = config.oracleUser,
              password = password
            )
          )
        }.leftMap(MigratorError.Connection(_))
      }
    yield provider

  private def configureWallet(config: MigratorConfig): Unit =
    config.oracleWallet.foreach { path =>
      val wallet = path.toAbsolutePath.toString
      System.setProperty("oracle.net.tns_admin", wallet)
      System.setProperty("oracle.net.wallet_location", s"(SOURCE=(METHOD=file)(METHOD_DATA=(DIRECTORY=$wallet)))")
      System.setProperty("oracle.net.ssl_server_dn_match", "true")
    }

object OracleSession:
  val bootstrapBlocks: List[String] =
    List(
      """
      begin
        execute immediate 'create table schema_control.schema_objects (
          id number generated by default as identity,
          kind varchar2(64) not null,
          object_name varchar2(256) not null,
          source_file varchar2(512) not null,
          depends_on clob,
          rollback_file varchar2(512),
          canonical_sql clob not null,
          content_sha256 varchar2(64) not null,
          applied_at timestamp with time zone,
          apply_status varchar2(16) default ''pending'' not null,
          last_error clob,
          created_at timestamp with time zone default systimestamp not null,
          updated_at timestamp with time zone default systimestamp not null,
          constraint schema_objects_pk primary key (id),
          constraint schema_objects_unique unique (kind, object_name),
          constraint schema_objects_status_chk check (apply_status in (''pending'', ''applied'', ''failed'', ''skipped''))
        )';
      exception
        when others then
          if sqlcode != -955 then raise; end if;
      end;
      /
      """,
      """
      begin
        execute immediate 'create table schema_control.schema_apply_log (
          log_id number generated by default as identity,
          kind varchar2(64) not null,
          object_name varchar2(256) not null,
          source_file varchar2(512) not null,
          action varchar2(32) not null,
          old_sha256 varchar2(64),
          new_sha256 varchar2(64),
          duration_ms number(10),
          error_text clob,
          applied_by varchar2(128),
          applied_at timestamp with time zone default systimestamp not null,
          constraint schema_apply_log_pk primary key (log_id)
        )';
      exception
        when others then
          if sqlcode != -955 then raise; end if;
      end;
      /
      """,
      """
      begin
        execute immediate 'create table schema_control.migration_locks (
          lock_name varchar2(128) primary key,
          locked_at timestamp with time zone not null,
          locked_by varchar2(128) not null
        )';
      exception
        when others then
          if sqlcode != -955 then raise; end if;
      end;
      /
      """,
      """
      create or replace view schema_control.schema_ready as
      select
        systimestamp as measured_at,
        count(*) as total_count,
        sum(case when apply_status = 'pending' then 1 else 0 end) as pending_count,
        sum(case when apply_status = 'failed' then 1 else 0 end) as failed_count,
        sum(case when apply_status in ('applied', 'skipped') then 1 else 0 end) as applied_count,
        case
          when count(*) > 0
           and sum(case when apply_status not in ('applied', 'skipped') then 1 else 0 end) = 0
           and sum(case when apply_status = 'failed' then 1 else 0 end) = 0
          then '1' else '0'
        end as ready,
        listagg(case when apply_status = 'failed' then kind || ':' || object_name end, ',' on overflow truncate '...')
          within group (order by kind, object_name) as failed_objects,
        max(updated_at) as last_updated_at,
        max(applied_at) as last_applied_at
      from schema_control.schema_objects
      """
    )

  val prepareSql: String =
    """
    merge into schema_control.schema_objects target
    using (
      select ? kind, ? object_name, ? source_file, ? depends_on, ? rollback_file,
             ? canonical_sql, ? content_sha256, ? apply_status
      from dual
    ) source
    on (target.kind = source.kind and target.object_name = source.object_name)
    when matched then update set
      target.source_file = source.source_file,
      target.depends_on = source.depends_on,
      target.rollback_file = source.rollback_file,
      target.canonical_sql = source.canonical_sql,
      target.content_sha256 = source.content_sha256,
      target.applied_at = case when source.apply_status = 'pending' then null else coalesce(target.applied_at, systimestamp) end,
      target.apply_status = source.apply_status,
      target.last_error = null,
      target.updated_at = systimestamp
    when not matched then insert (
      kind, object_name, source_file, depends_on, rollback_file, canonical_sql, content_sha256,
      applied_at, apply_status, last_error, updated_at
    ) values (
      source.kind, source.object_name, source.source_file, source.depends_on, source.rollback_file,
      source.canonical_sql, source.content_sha256,
      case when source.apply_status = 'pending' then null else systimestamp end,
      source.apply_status, null, systimestamp
    )
    """

  val applyLogSql: String =
    """
    insert into schema_control.schema_apply_log (
      kind, object_name, source_file, action, old_sha256, new_sha256,
      duration_ms, error_text, applied_by
    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
