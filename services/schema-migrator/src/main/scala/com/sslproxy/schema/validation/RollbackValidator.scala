package com.sslproxy.schema.validation

import com.sslproxy.schema.discovery.SqlFile
import com.sslproxy.schema.parser.HeaderParser

import java.nio.file.{Files, Path}

object RollbackValidator:
  def validate(files: List[SqlFile]): List[String] =
    files.flatMap { file =>
      val sql = Files.readString(file.path)
      HeaderParser.value(sql, "rollback").toList.flatMap { rollback =>
        resolveExistingRollbackPath(file, rollback) match
          case None => List(s"${file.relativePath}: rollback file '$rollback' does not exist")
          case Some(path) =>
            val rollbackSql = Files.readString(path)
            if rollbackSql.trim.isEmpty then
              List(s"${file.relativePath}: rollback file '$path' is empty")
            else Nil
      }
    }

  def resolveExistingRollbackPath(file: SqlFile, rollback: String): Option[Path] =
    candidates(file, rollback).find(Files.exists(_))

  def candidates(file: SqlFile, rollback: String): List[Path] =
    val reference = Path.of(rollback)
    if reference.isAbsolute then List(reference)
    else
      val base = List(reference)
      val sqlDirCandidates =
        Option(file.path.getParent)
          .flatMap(parent => Option(parent.getParent))
          .toList
          .flatMap { sqlDir =>
            val stripped =
              if reference.getNameCount > 0 && reference.getName(0).toString == "sql" then
                List(sqlDir.resolve(reference.subpath(1, reference.getNameCount)))
              else Nil
            val repoRelative = Option(sqlDir.getParent).toList.map(_.resolve(reference))
            List(sqlDir.resolve(reference)) ::: stripped ::: repoRelative
          }
      val fileRelative = Option(file.path.getParent).toList.map(_.resolve(reference))
      (base ::: sqlDirCandidates ::: fileRelative).distinct
