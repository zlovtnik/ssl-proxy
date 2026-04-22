require "test_helper"

class BacklogRetryServiceTest < ActiveSupport::TestCase
  FakeEntry = Struct.new(:dedupe_key, :stream_name, :payload)
  FakePublisher = Struct.new(:published) do
    def publish(subject, payload)
      published << [subject, payload]
    end
  end

  test "publishes original backlog subject and payload" do
    entry = FakeEntry.new("key-1", "wireless.audit", "{\"ok\":true}")
    BacklogStatus.stub(:find, entry) do
      publisher = FakePublisher.new([])
      result = BacklogRetryService.new("key-1", publisher: publisher).call

      assert_equal [["wireless.audit", "{\"ok\":true}"]], publisher.published
      assert_equal "wireless.audit", result.subject
    end
  end
end
