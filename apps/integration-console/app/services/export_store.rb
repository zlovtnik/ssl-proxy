require "digest/sha1"

class ExportStore
  EXPORT_PREFIX = "exports"
  CLEANUP_AGE = 1.hour
  CONTENT_TYPE = "text/csv"

  class Error < StandardError; end

  def self.key_for(type:, query:, sort:, direction:)
    digest = Digest::SHA1.hexdigest([type, query.to_s.strip, sort.to_s, direction.to_s].join("\0"))
    "#{EXPORT_PREFIX}/#{type}/#{digest}.csv"
  end

  def self.fetch_or_generate(key:, ttl:, &block)
    new.fetch_or_generate(key: key, ttl: ttl, &block)
  end

  def initialize(client: Aws::S3::Client.new, presigner: nil, bucket: IntegrationConsole::Minio.bucket)
    @client = client
    @presigner = presigner || Aws::S3::Presigner.new(client: client)
    @bucket = bucket
  end

  def fetch_or_generate(key:, ttl:)
    cleanup_stale_exports
    return presigned_url(key, ttl: ttl) if fresh?(key, ttl: ttl)

    body = yield
    put(key, body)
    presigned_url(key, ttl: ttl)
  rescue Aws::Errors::ServiceError => error
    raise Error, error.message
  end

  def fresh?(key, ttl:)
    object = @client.head_object(bucket: @bucket, key: key)
    object.last_modified && object.last_modified >= ttl.ago
  rescue Aws::S3::Errors::NotFound, Aws::S3::Errors::NoSuchKey
    false
  end

  def put(key, body)
    @client.put_object(bucket: @bucket, key: key, body: body, content_type: CONTENT_TYPE)
  end

  def presigned_url(key, ttl:)
    @presigner.presigned_url(:get_object, bucket: @bucket, key: key, expires_in: ttl.to_i)
  end

  def cleanup_stale_exports
    cutoff = CLEANUP_AGE.ago
    token = nil

    loop do
      response = @client.list_objects_v2(bucket: @bucket, prefix: "#{EXPORT_PREFIX}/", continuation_token: token)
      stale_keys = response.contents.filter_map do |object|
        object.key if object.last_modified && object.last_modified < cutoff
      end
      delete_keys(stale_keys) if stale_keys.any?
      break unless response.is_truncated

      token = response.next_continuation_token
    end
  rescue Aws::S3::Errors::NoSuchBucket
    raise
  end

  private

  def delete_keys(keys)
    @client.delete_objects(
      bucket: @bucket,
      delete: {
        objects: keys.map { |key| { key: key } },
        quiet: true
      }
    )
  end
end
