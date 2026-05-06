class AddPskToAuthorizedWirelessNetworks < ActiveRecord::Migration[7.2]
  def up
    add_column :authorized_wireless_networks, :psk_ciphertext, :text, if_not_exists: true

    return unless column_exists?(:authorized_wireless_networks, :psk)

    AuthorizedWirelessNetwork.reset_column_information
    rows = AuthorizedWirelessNetwork.connection.exec_query(
      "SELECT id, psk FROM authorized_wireless_networks WHERE psk IS NOT NULL AND psk_ciphertext IS NULL"
    )
    rows.each do |row|
      network = AuthorizedWirelessNetwork.unscoped.find(row["id"])
      network.psk = row["psk"]
      network.save!(validate: false)
    end
  end
  
  def down
    remove_column :authorized_wireless_networks, :psk_ciphertext, if_exists: true
  end
end
