class SyncRecord < ActiveRecord::Base
  self.abstract_class = true

  connects_to database: { writing: :sync, reading: :sync }

  READ_ONLY_MESSAGE = "is backed by the sync database"

  def readonly?
    true
  end

  def delete
    raise_readonly_record!
  end

  before_destroy do
    raise_readonly_record!
  end

  class << self
    def delete(...)
      raise_readonly_record!
    end

    def delete_all(...)
      raise_readonly_record!
    end

    def update_all(...)
      raise_readonly_record!
    end

    def insert(...)
      raise_readonly_record!
    end

    def insert!(...)
      raise_readonly_record!
    end

    def insert_all(...)
      raise_readonly_record!
    end

    def insert_all!(...)
      raise_readonly_record!
    end

    def upsert_all(...)
      raise_readonly_record!
    end

    private

    def raise_readonly_record!
      raise ActiveRecord::ReadOnlyRecord, "#{name} #{READ_ONLY_MESSAGE}"
    end
  end

  private

  def raise_readonly_record!
    raise ActiveRecord::ReadOnlyRecord, "#{self.class.name} #{READ_ONLY_MESSAGE}"
  end
end
