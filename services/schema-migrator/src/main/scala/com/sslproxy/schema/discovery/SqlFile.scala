package com.sslproxy.schema.discovery

import java.nio.file.Path

final case class SqlFile(folder: String, path: Path, name: String, relativePath: String = ""):
  def relativePathResolved: String =
    if relativePath.nonEmpty then relativePath
    else s"$folder/$name"

final case class DiscoveryResult(files: List[SqlFile], warnings: List[String])

