class AddPskToAuthorizedWirelessNetworks < ActiveRecord::Migration[7.2]
  def change
    add_column :authorized_wireless_networks, :psk, :text, if_not_exists: true
  end
end
