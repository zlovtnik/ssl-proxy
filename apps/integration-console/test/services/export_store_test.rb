require "test_helper"
require "ostruct"

class ExportStoreTest < ActiveSupport::TestCase
  FakeObject = Struct.new(:key, :last_modified, keyword_init: true)

  class FakeClient
    attr_reader :deleted_keys, :put_objects

    def initialize(objects = {})
      @objects = objects
      @deleted_keys = []
      @put_objects = []
    end

    def head_object(bucket:, key:)
      object = @objects.fetch(key) { raise Aws::S3::Errors::NotFound.new(nil, "missing") }
      OpenStruct.new(last_modified: object.last_modified)
    end

    def put_object(bucket:, key:, body:, content_type:, content_disposition: nil)
      @put_objects << { key: key, body: body, content_type: content_type, content_disposition: content_disposition }
      @objects[key] = FakeObject.new(key: key, last_modified: Time.current)
    end

    def list_objects_v2(bucket:, prefix:, continuation_token: nil)
      OpenStruct.new(
        contents: @objects.values.select { |object| object.key.start_with?(prefix) },
        is_truncated: false,
        next_continuation_token: nil
      )
    end

    def delete_objects(bucket:, delete:)
      delete.fetch(:objects).each do |object|
        key = object.fetch(:key)
        @deleted_keys << key
        @objects.delete(key)
      end
    end
  end

  class FakePresigner
    def presigned_url(_operation, bucket:, key:, expires_in:, response_content_disposition: nil)
      suffix = response_content_disposition ? "&disposition=#{response_content_disposition}" : ""
      "http://minio.test/#{bucket}/#{key}?ttl=#{expires_in}#{suffix}"
    end
  end

  test "returns fresh presigned url without regenerating csv" do
    client = FakeClient.new(
      "exports/audit/fresh.csv" => FakeObject.new(key: "exports/audit/fresh.csv", last_modified: Time.current)
    )
    store = ExportStore.new(client: client, presigner: FakePresigner.new, bucket: "exports")

    generated = false
    url = store.fetch_or_generate(key: "exports/audit/fresh.csv", ttl: 5.minutes) do
      generated = true
      "csv"
    end

    assert_equal "http://minio.test/exports/exports/audit/fresh.csv?ttl=300", url
    assert_not generated
    assert_empty client.put_objects
  end

  test "generates uploads and cleans stale export objects" do
    client = FakeClient.new(
      "exports/audit/stale.csv" => FakeObject.new(key: "exports/audit/stale.csv", last_modified: 2.hours.ago)
    )
    store = ExportStore.new(client: client, presigner: FakePresigner.new, bucket: "exports")

    url = store.fetch_or_generate(key: "exports/audit/new.csv", ttl: 5.minutes) { "new,csv\n" }

    assert_equal "http://minio.test/exports/exports/audit/new.csv?ttl=300", url
    assert_equal ["exports/audit/stale.csv"], client.deleted_keys
    assert_equal "exports/audit/new.csv", client.put_objects.first.fetch(:key)
    assert_equal "new,csv\n", client.put_objects.first.fetch(:body)
    assert_equal "text/csv", client.put_objects.first.fetch(:content_type)
  end

  test "adds attachment disposition for named exports" do
    client = FakeClient.new
    store = ExportStore.new(client: client, presigner: FakePresigner.new, bucket: "exports")

    url = store.fetch_or_generate(key: "exports/audit/new.csv", ttl: 5.minutes, filename: "audit logs.csv") { "csv\n" }

    assert_includes url, "attachment; filename=\"audit_logs.csv\""
    assert_equal "attachment; filename=\"audit_logs.csv\"", client.put_objects.first.fetch(:content_disposition)
  end
end
