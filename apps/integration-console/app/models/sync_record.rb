class SyncRecord < ActiveRecord::Base
  self.abstract_class = true

  connects_to database: { writing: :sync, reading: :sync }

  def readonly?
    true
  end

  before_destroy do
    raise ActiveRecord::ReadOnlyRecord, "#{self.class.name} is backed by the sync database"
  end
end
