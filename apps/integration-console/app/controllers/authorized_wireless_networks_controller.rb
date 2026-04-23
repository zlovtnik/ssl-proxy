class AuthorizedWirelessNetworksController < ApplicationController
  SORTS = {
    "enabled" => :enabled,
    "location_id" => :location_id,
    "ssid" => :ssid,
    "bssid" => :bssid,
    "label" => :label,
    "updated_at" => :updated_at
  }.freeze

  def index
    @authorized_wireless_networks = apply_sort(AuthorizedWirelessNetwork.ordered, SORTS, default_sort: :ssid, default_direction: :asc)
  end

  def new
    @authorized_wireless_network = AuthorizedWirelessNetwork.new(enabled: true)
  end

  def create
    @authorized_wireless_network = AuthorizedWirelessNetwork.new(authorized_wireless_network_params)
    if @authorized_wireless_network.save
      redirect_to authorized_wireless_networks_path, notice: "Authorized wireless network saved"
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
    @authorized_wireless_network = AuthorizedWirelessNetwork.find(params[:id])
  end

  def update
    @authorized_wireless_network = AuthorizedWirelessNetwork.find(params[:id])
    if @authorized_wireless_network.update(authorized_wireless_network_params)
      redirect_to authorized_wireless_networks_path, notice: "Authorized wireless network updated"
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    AuthorizedWirelessNetwork.find(params[:id]).destroy!
    redirect_to authorized_wireless_networks_path, notice: "Authorized wireless network removed"
  end

  private

  def authorized_wireless_network_params
    params.require(:authorized_wireless_network).permit(:ssid, :bssid, :location_id, :label, :enabled, :notes)
  end
end
