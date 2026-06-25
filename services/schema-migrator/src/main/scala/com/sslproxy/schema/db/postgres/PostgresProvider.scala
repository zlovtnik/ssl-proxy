package com.sslproxy.schema.db.postgres

import cats.effect.{IO, Resource}
import cats.syntax.all.*
import com.sslproxy.schema.config.MigratorConfig
import com.sslproxy.schema.db.{DbProvider, DbSession, JdbcConnectionConfig, JdbcSupport}
import com.sslproxy.schema.db.syntax.SqlDialect
import com.sslproxy.schema.engine.*
import com.sslproxy.schema.error.MigratorError
import com.sslproxy.schema.validation.RollbackValidator

import java.net.{URI, URLDecoder}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.sql.{Connection, ResultSet, SQLException}
import scala.jdk.CollectionConverters.*

final class PostgresProvider(config: JdbcConnectionConfig) extends DbProvider:
  override val dialect: SqlDialect = SqlDialect.Postgres

  override def session: Resource[IO, DbSession] =
    JdbcSupport.connection(config).map(PostgresSession(_))

final class PostgresSession(connection: Connection) extends DbSession:
  import JdbcSupport.*

  override def checkConnection: IO[Unit] =
    IO.blocking(queryOne(connection, "select 1")(_.getInt(1))).void

  override def bootstrap: IO[Unit] =
    IO.blocking(executeStatement(connection, PostgresSession.bootstrapSql)).adaptError {
      case error: SQLException => MigratorError.Apply(s"schema_control bootstrap failed: ${error.getMessage}", error)
    }

  override def acquireLock: IO[Unit] =
    IO.blocking {
      val rows = queryPrepared(connection, "select pg_try_advisory_lock(?)") { statement =>
        statement.setLong(1, PostgresSession.applyLockKey)
      }(_.getBoolean(1))
      if !rows.headOption.contains(true) then
        throw MigratorError.Apply(
          s"schema apply lock ${PostgresSession.applyLockKey} (${PostgresSession.applyLockNamespace}) is already held"
        )
    }

  override def releaseLock: IO[Unit] =
    IO.blocking {
      val rows = queryPrepared(connection, "select pg_advisory_unlock(?)") { statement =>
        statement.setLong(1, PostgresSession.applyLockKey)
      }(_.getBoolean(1))
      if !rows.headOption.contains(true) then
        throw MigratorError.LockNotHeld(
          s"schema apply lock ${PostgresSession.applyLockKey} (${PostgresSession.applyLockNamespace}) was not held"
        )
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

      val statement = connection.prepareStatement(PostgresSession.prepareSql)
      try
        statement.setString(1, objectDef.kind)
        statement.setString(2, objectDef.objectName)
        statement.setString(3, objectDef.sourceFile)
        statement.setArray(4, connection.createArrayOf("text", objectDef.dependsOn.toArray[AnyRef]))
        objectDef.rollbackFile.fold(statement.setNull(5, java.sql.Types.VARCHAR))(statement.setString(5, _))
        statement.setString(6, objectDef.canonicalSql)
        statement.setString(7, objectDef.sha256)
        statement.setString(8, status)
        statement.setString(9, status)
        statement.executeUpdate()
      finally statement.close()

      PreparedObject(objectDef, oldSha, needsApply)
    }.adaptError { case error: SQLException =>
      MigratorError.Apply(
        s"failed to prepare schema control state for ${objectDef.kind}:${objectDef.objectName}: ${error.getMessage}",
        error
      )
    }

  override def recordSkipped(prepared: PreparedObject): IO[Unit] =
    IO.blocking(insertApplyLog(prepared.objectDef, "skipped", prepared.oldSha256, None, None))

  override def executeObject(prepared: PreparedObject): IO[Unit] =
    if prepared.objectDef.transactional then executeTransactional(prepared)
    else executeNonTransactional(prepared)

  private def executeTransactional(prepared: PreparedObject): IO[Unit] =
    IO.blocking {
      val started = System.nanoTime()
      connection.setAutoCommit(false)
      try
        executeStatement(connection, prepared.objectDef.rawSql)
        recordAppliedUnsafe(prepared, durationMs(started))
        connection.commit()
      catch
        case error: SQLException =>
          connection.rollback()
          connection.setAutoCommit(true)
          val formatted = sqlError(prepared.objectDef.sourceFile, error, "postgres")
          recordFailedUnsafe(prepared, formatted, durationMs(started))
          throw MigratorError.Apply(formatted, error)
      finally connection.setAutoCommit(true)
    }

  private def executeNonTransactional(prepared: PreparedObject): IO[Unit] =
    IO.blocking {
      val started = System.nanoTime()
      connection.setAutoCommit(true)
      try
        executeStatement(connection, prepared.objectDef.rawSql)
        try recordAppliedUnsafe(prepared, durationMs(started))
        catch
          case error: SQLException =>
            throw MigratorError.NonRetryableApply(
              s"${prepared.objectDef.sourceFile}: applied SQL but failed to record migration state: ${error.getMessage}",
              error
            )
      catch
        case error: SQLException =>
          val formatted = sqlError(prepared.objectDef.sourceFile, error, "postgres")
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
      connection.setAutoCommit(false)
      try
        executeStatement(connection, rollbackSql)
        executePrepared(
          connection,
          """
          update schema_control.schema_objects
             set apply_status = 'pending',
                 applied_at = null,
                 last_error = null,
                 updated_at = now()
           where kind = ? and object_name = ?
          """
        ) { statement =>
          statement.setString(1, target.kind)
          statement.setString(2, target.objectName)
        }
        insertRollbackLog(target, durationMs(started))
        connection.commit()
      catch
        case error: SQLException =>
          connection.rollback()
          throw MigratorError.Apply(sqlError(rollbackPath.toString, error, "postgres"), error)
      finally connection.setAutoCommit(true)
    }

  override def fetchStatus: IO[List[ObjectStatus]] =
    IO.blocking {
      try
        queryList(
          connection,
          """
          select kind, object_name, source_file, apply_status,
                 content_sha256,
                 to_char(applied_at, 'YYYY-MM-DD HH24:MI:SS') as applied_at,
                 last_error
            from schema_control.schema_objects
           order by kind, object_name
          """
        )(readObjectStatus)
      catch
        case error: java.sql.SQLException =>
          List.empty
    }

  override def fetchReady: IO[SchemaReadyStatus] =
    IO.blocking {
      try
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
      catch
        case error: java.sql.SQLException =>
          SchemaReadyStatus(0, 0, 0, 0, ready = false, Nil, None, None)
    }

  override def checkReady: IO[Boolean] =
    fetchReady.map(_.ready)

  private def recordAppliedUnsafe(prepared: PreparedObject, durationMs: Int): Unit =
    executePrepared(
      connection,
      """
      update schema_control.schema_objects
         set apply_status = 'applied',
             applied_at = now(),
             last_error = null,
             updated_at = now()
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
             updated_at = now()
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
    executePrepared(connection, PostgresSession.applyLogSql) { statement =>
      statement.setString(1, objectDef.kind)
      statement.setString(2, objectDef.objectName)
      statement.setString(3, objectDef.sourceFile)
      statement.setString(4, action)
      oldSha.fold(statement.setNull(5, java.sql.Types.VARCHAR))(statement.setString(5, _))
      statement.setString(6, objectDef.sha256)
      durationMs.fold(statement.setNull(7, java.sql.Types.INTEGER))(statement.setInt(7, _))
      errorText.fold(statement.setNull(8, java.sql.Types.VARCHAR))(statement.setString(8, _))
      statement.setString(9, appliedBy)
    }

  private def insertRollbackLog(target: RollbackTarget, durationMs: Int): Unit =
    executePrepared(connection, PostgresSession.applyLogSql) { statement =>
      statement.setString(1, target.kind)
      statement.setString(2, target.objectName)
      statement.setString(3, target.sourceFile)
      statement.setString(4, "rolled_back")
      statement.setString(5, target.contentSha256)
      statement.setString(6, target.contentSha256)
      statement.setInt(7, durationMs)
      statement.setNull(8, java.sql.Types.VARCHAR)
      statement.setString(9, appliedBy)
    }

  private def fetchRollbackTargetUnsafe(objectName: String): RollbackTarget =
    val allRows = queryPrepared(
      connection,
      """
      select kind, object_name, source_file, content_sha256, rollback_file
        from schema_control.schema_objects
       where object_name = ?
       order by kind, object_name
      """
    )(_.setString(1, objectName)) { row =>
      val rawRollback = row.getString("rollback_file")
      val rollback = if rawRollback == null then "" else rawRollback
      Some(
        RollbackTarget(
          kind = row.getString("kind"),
          objectName = row.getString("object_name"),
          sourceFile = row.getString("source_file"),
          contentSha256 = row.getString("content_sha256"),
          rollbackFile = rollback
        )
      )
    }.flatten

    allRows match
      case Nil => throw MigratorError.Apply(s"no tracked schema object named $objectName")
      case target :: Nil =>
        if target.rollbackFile == null || target.rollbackFile.isEmpty then
          throw MigratorError.Apply(s"no rollback SQL tracked for $objectName")
        target
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
    val array = Option(row.getArray("failed_objects"))
      .map(_.getArray.asInstanceOf[Array[String]].toList)
      .getOrElse(Nil)
    SchemaReadyStatus(
      totalCount = row.getLong("total_count"),
      pendingCount = row.getLong("pending_count"),
      failedCount = row.getLong("failed_count"),
      appliedCount = row.getLong("applied_count"),
      ready = row.getBoolean("ready"),
      failedObjects = array,
      lastUpdatedAt = Option(row.getString("last_updated_at")),
      lastAppliedAt = Option(row.getString("last_applied_at"))
    )

  private def appliedBy: String =
    s"${sys.env.getOrElse("HOSTNAME", "unknown-host")}:${ProcessHandle.current().pid()}"

object PostgresProvider:
  def fromConfig(config: MigratorConfig): IO[PostgresProvider] =
    IO.fromEither {
      config.databaseUrl
        .orElse(sys.env.get("DATABASE_URL"))
        .toRight("DATABASE_URL is required for Postgres")
        .flatMap(normalize)
        .map(PostgresProvider(_))
        .leftMap(message => MigratorError.Connection(message))
    }

  def normalize(raw: String): Either[String, JdbcConnectionConfig] =
    if raw.startsWith("jdbc:postgresql://") then
      Right(JdbcConnectionConfig("org.postgresql.Driver", raw))
    else if raw.startsWith("postgres://") || raw.startsWith("postgresql://") then
      parsePostgresUri(raw)
    else Left("Postgres URL must start with postgres://, postgresql://, or jdbc:postgresql://")

  private def parsePostgresUri(raw: String): Either[String, JdbcConnectionConfig] =
    Either.catchNonFatal(URI(raw)).leftMap(error => s"invalid Postgres URL: ${error.getMessage}").flatMap { uri =>
      if uri.getHost == null then
        Left("invalid Postgres URL: host is required")
      else
        val path = Option(uri.getRawPath).filter(_.nonEmpty).getOrElse("/")
        val port = if uri.getPort >= 0 then s":${uri.getPort}" else ""
        val query = Option(uri.getRawQuery).filter(_.nonEmpty).map(q => s"?$q").getOrElse("")
        val url = s"jdbc:postgresql://${uri.getHost}$port$path$query"
        val userInfo = Option(uri.getRawUserInfo).getOrElse("")
        val parts = userInfo.split(":", 2)
        val user = parts.headOption.filter(_.nonEmpty).map(decode)
        val pass = parts.drop(1).headOption.filter(_.nonEmpty).map(decode)
        Right(JdbcConnectionConfig("org.postgresql.Driver", url, user, pass))
    }

  private def decode(value: String): String =
    URLDecoder.decode(value, StandardCharsets.UTF_8)

object PostgresSession:
  val applyLockNamespace = "ssl-proxy:schema-migrator:schema-apply"
  val applyLockKey: Long = advisoryLockKey(applyLockNamespace)

  private def advisoryLockKey(namespace: String): Long =
    var hash = BigInt("cbf29ce484222325", 16)
    val prime = BigInt("100000001b3", 16)
    val mask = BigInt("ffffffffffffffff", 16)
    namespace.getBytes(StandardCharsets.UTF_8).foreach { byte =>
      hash = (hash ^ BigInt(byte & 0xff)) * prime & mask
    }
    (hash & BigInt("7fffffffffffffff", 16)).toLong

  val bootstrapSql: String =
    """
    create schema if not exists schema_control;

    create table if not exists schema_control.schema_objects (
      id              bigserial primary key,
      kind            text        not null,
      object_name     text        not null,
      source_file     text        not null,
      depends_on      text[]      not null default '{}',
      rollback_file   text,
      canonical_sql   text        not null,
      content_sha256  text        not null,
      applied_at      timestamptz,
      apply_status    text        not null default 'pending',
      last_error      text,
      created_at      timestamptz not null default now(),
      updated_at      timestamptz not null default now(),
      constraint schema_objects_unique unique (kind, object_name),
      constraint schema_objects_status_chk check (
        apply_status in ('pending', 'applied', 'failed', 'skipped')
      )
    );

    alter table schema_control.schema_objects
      add column if not exists rollback_file text;

    create table if not exists schema_control.schema_apply_log (
      log_id        bigserial primary key,
      kind          text        not null,
      object_name   text        not null,
      source_file   text        not null,
      action        text        not null,
      old_sha256    text,
      new_sha256    text,
      duration_ms   integer,
      error_text    text,
      applied_by    text,
      applied_at    timestamptz not null default now()
    );

    create index if not exists schema_apply_log_object_idx
      on schema_control.schema_apply_log(kind, object_name, applied_at desc);

    create or replace view schema_control.schema_ready as
    select
      now() as measured_at,
      count(*)::bigint as total_count,
      count(*) filter (where apply_status = 'pending')::bigint as pending_count,
      count(*) filter (where apply_status = 'failed')::bigint as failed_count,
      count(*) filter (where apply_status in ('applied', 'skipped'))::bigint as applied_count,
      (
        count(*) > 0
        and coalesce(bool_and(apply_status in ('applied', 'skipped')), false)
      ) as all_applied,
      (
        count(*) > 0
        and coalesce(bool_and(apply_status in ('applied', 'skipped')), false)
        and count(*) filter (where apply_status = 'failed') = 0
      ) as ready,
      coalesce(
        array_agg(kind || ':' || object_name order by kind, object_name)
          filter (where apply_status = 'failed'),
        array[]::text[]
      ) as failed_objects,
      max(updated_at) as last_updated_at,
      max(applied_at) as last_applied_at
    from schema_control.schema_objects;
    """

  val prepareSql: String =
    """
    insert into schema_control.schema_objects (
      kind, object_name, source_file, depends_on, rollback_file, canonical_sql, content_sha256,
      applied_at, apply_status, last_error, updated_at
    ) values (
      ?, ?, ?, ?, ?, ?, ?,
      case when ?::text = 'pending' then null else now() end,
      ?, null, now()
    )
    on conflict (kind, object_name) do update set
      source_file = excluded.source_file,
      depends_on = excluded.depends_on,
      rollback_file = excluded.rollback_file,
      canonical_sql = excluded.canonical_sql,
      content_sha256 = excluded.content_sha256,
      applied_at = case
        when excluded.apply_status = 'pending' then null
        else coalesce(schema_control.schema_objects.applied_at, now())
      end,
      apply_status = excluded.apply_status,
      last_error = null,
      updated_at = now()
    """

  val applyLogSql: String =
    """
    insert into schema_control.schema_apply_log (
      kind, object_name, source_file, action, old_sha256, new_sha256,
      duration_ms, error_text, applied_by
    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
