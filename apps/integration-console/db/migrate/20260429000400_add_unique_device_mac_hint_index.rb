class AddUniqueDeviceMacHintIndex < ActiveRecord::Migration[7.2]
  disable_ddl_transaction!

  INDEX_NAME = "index_devices_on_lower_mac_hint_unique".freeze

  def up
    duplicate = select_one(<<~SQL.squish)
      SELECT lower(mac_hint) AS normalized_mac_hint, COUNT(*) AS duplicate_count
      FROM devices
      WHERE mac_hint IS NOT NULL
      GROUP BY lower(mac_hint)
      HAVING COUNT(*) > 1
      LIMIT 1
    SQL

    if duplicate.present?
      raise ActiveRecord::MigrationError,
        "Cannot add unique mac_hint index: lower(mac_hint)=#{duplicate["normalized_mac_hint"]} has #{duplicate["duplicate_count"]} rows"
    end

    add_index :devices,
      "lower(mac_hint)",
      unique: true,
      where: "mac_hint IS NOT NULL",
      name: INDEX_NAME,
      algorithm: :concurrently
  end

  def down
    remove_index :devices, name: INDEX_NAME, algorithm: :concurrently
  end
end
