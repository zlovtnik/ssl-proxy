package com.sslproxy.schema.config

import java.nio.file.Path
import scala.concurrent.duration.FiniteDuration

enum DbKind:
  case Postgres, Oracle

object DbKind:
  def parse(value: String): Either[String, DbKind] =
    value.trim.toLowerCase match
      case "postgres" | "postgresql" => Right(Postgres)
      case "oracle"                  => Right(Oracle)
      case other                     => Left(s"unsupported db kind '$other'")

final case class MigratorConfig(
    dbKind: DbKind,
    databaseUrl: Option[String],
    sqlDir: Path,
    dryRun: Boolean,
    verbose: Boolean,
    continueOnError: Boolean,
    connectRetries: Int,
    connectRetryBackoff: FiniteDuration,
    oracleWallet: Option[Path],
    oracleTnsAlias: Option[String],
    oracleUser: Option[String],
    oraclePasswordFile: Option[Path],
    json: Boolean
)

