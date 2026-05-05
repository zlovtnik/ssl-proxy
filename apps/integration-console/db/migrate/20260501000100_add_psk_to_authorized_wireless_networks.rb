class AddPskToAuthorizedWirelessNetworks < ActiveRecord::Migration[7.2]
  def up
    add_column :authorized_wireless_networks, :psk_ciphertext, :text, if_not_exists: true

    return unless column_exists?(:authorized_wireless_networks, :psk)

    AuthorizedWirelessNetwork.reset_column_information
    AuthorizedWirelessNetwork
      .unscoped
      .where("psk IS NOT NULL AND psk_ciphertext IS NULL")
      .find_each do |network|
        network.psk = network.read_attribute_before_type_cast("psk")
        network.save!(validate: false)
      end
  end
  
  def down
    remove_column :authorized_wireless_networks, :psk_ciphertext, if_exists: true
  end
end
