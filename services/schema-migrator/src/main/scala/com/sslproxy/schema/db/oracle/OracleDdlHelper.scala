package com.sslproxy.schema.db.oracle

import java.sql.Connection

object OracleDdlHelper:
  def executeSql(connection: Connection, sql: String): Unit =
    splitExecutableBlocks(sql).foreach { statementSql =>
      val statement = connection.createStatement()
      try statement.execute(stripTrailingSemicolon(statementSql))
      finally statement.close()
    }

  def splitExecutableBlocks(sql: String): List[String] =
    val blocks = scala.collection.mutable.ListBuffer.empty[String]
    val current = new StringBuilder
    sql.linesIterator.foreach { line =>
      if line.trim == "/" then
        appendCurrent(blocks, current)
      else current.append(line).append('\n')
    }
    appendCurrent(blocks, current)
    blocks.toList

  private def appendCurrent(blocks: scala.collection.mutable.ListBuffer[String], current: StringBuilder): Unit =
    val text = current.toString.trim
    if text.nonEmpty then blocks.append(text)
    current.clear()

  private def stripTrailingSemicolon(sql: String): String =
    val trimmed = sql.trim
    val lower = trimmed.toLowerCase
    if lower.startsWith("begin") || lower.startsWith("declare") then trimmed
    else if trimmed.endsWith(";") then trimmed.dropRight(1).trim
    else trimmed
