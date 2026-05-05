class AddPskToAuthorizedWirelessNetworks < ActiveRecord::Migration[7.2]
  def up
    add_column :authorized_wireless_networks, :psk_ciphertext, :text, if_not_exists: true
    
    execute <<~SQL
      UPDATE authorized_wireless_networks
      SET psk_ciphertext = psk
      WHERE psk IS NOT NULL AND psk_ciphertext IS NULL
    SQL
  end
  
  def down
    remove_column :authorized_wireless_networks, :psk_ciphertext, if_exists: true
  end
end
