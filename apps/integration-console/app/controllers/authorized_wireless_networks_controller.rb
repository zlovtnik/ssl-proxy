class AuthorizedWirelessNetworksController < ApplicationController
  SORTS = {
    "enabled" => :enabled,
    "location_id" => :location_id,
    "ssid" => :ssid,
    "bssid" => :bssid,
    "label" => :label,
    "updated_at" => :updated_at
  }.freeze

  FILTERS = {
    "enabled" => { column: :enabled, type: :boolean },
    "location_id" => :location_id,
    "ssid" => :ssid,
    "bssid" => :bssid,
    "label" => :label,
    "updated_at" => { column: :updated_at, type: :date }
  }.freeze

  def index
    @authorized_wireless_networks = apply_grid_filters(AuthorizedWirelessNetwork.ordered, FILTERS)
    @authorized_wireless_networks = apply_sort(@authorized_wireless_networks, SORTS, default_sort: :ssid, default_direction: :asc)
    @authorized_wireless_page_payload = authorized_wireless_page_payload(rows: @authorized_wireless_networks, mode: "index")

    respond_to do |format|
      format.html
      format.json { render json: @authorized_wireless_page_payload }
    end
  end

  def new
    @authorized_wireless_network = AuthorizedWirelessNetwork.new(enabled: true)
    @authorized_wireless_page_payload = authorized_wireless_page_payload(rows: [], mode: "form", network: @authorized_wireless_network)
  end

  def create
    @authorized_wireless_network = AuthorizedWirelessNetwork.new(authorized_wireless_network_params)
    if @authorized_wireless_network.save
      respond_to do |format|
        format.html { redirect_to authorized_wireless_networks_path, notice: "Authorized wireless network saved", status: :see_other }
        format.json { render json: { network: authorized_wireless_network_payload(@authorized_wireless_network), redirectUrl: authorized_wireless_networks_path }, status: :created }
      end
    else
      render_authorized_wireless_errors(:new)
    end
  end

  def edit
    @authorized_wireless_network = AuthorizedWirelessNetwork.find(params[:id])
    @authorized_wireless_page_payload = authorized_wireless_page_payload(rows: [], mode: "form", network: @authorized_wireless_network)
  end

  def update
    @authorized_wireless_network = AuthorizedWirelessNetwork.find(params[:id])
    if @authorized_wireless_network.update(authorized_wireless_network_params)
      respond_to do |format|
        format.html { redirect_to authorized_wireless_networks_path, notice: "Authorized wireless network updated", status: :see_other }
        format.json { render json: { network: authorized_wireless_network_payload(@authorized_wireless_network), redirectUrl: authorized_wireless_networks_path } }
      end
    else
      render_authorized_wireless_errors(:edit)
    end
  end

  def destroy
    AuthorizedWirelessNetwork.find(params[:id]).destroy!
    respond_to do |format|
      format.html { redirect_to authorized_wireless_networks_path, notice: "Authorized wireless network removed", status: :see_other }
      format.json { head :no_content }
    end
  end

  private

  def authorized_wireless_network_params
    params.require(:authorized_wireless_network).permit(:ssid, :bssid, :location_id, :label, :enabled, :notes)
  end

  def render_authorized_wireless_errors(template)
    @authorized_wireless_page_payload = authorized_wireless_page_payload(rows: [], mode: "form", network: @authorized_wireless_network)
    respond_to do |format|
      format.html { render template, status: :unprocessable_entity }
      format.json { render json: { errors: @authorized_wireless_network.errors.full_messages, network: authorized_wireless_network_payload(@authorized_wireless_network) }, status: :unprocessable_entity }
    end
  end

  def authorized_wireless_page_payload(rows:, mode:, network: nil)
    {
      mode: mode,
      rows: rows.map { |row| authorized_wireless_network_payload(row) },
      current: network && authorized_wireless_network_payload(network),
      errors: network&.errors&.full_messages || [],
      sortKey: @sort || "ssid",
      sortDirection: @direction || "asc",
      filters: parsed_grid_filters,
      endpoints: {
        index: authorized_wireless_networks_path,
        create: authorized_wireless_networks_path
      }
    }
  end

  def authorized_wireless_network_payload(network)
    {
      id: network.id,
      enabled: network.enabled,
      location_id: network.location_id,
      ssid: network.ssid,
      bssid: network.bssid,
      label: network.label,
      notes: network.notes,
      match_label: network.match_label,
      updated_at: network.updated_at&.iso8601,
      edit_url: network.persisted? ? edit_authorized_wireless_network_path(network) : nil,
      update_url: network.persisted? ? authorized_wireless_network_path(network) : nil,
      delete_url: network.persisted? ? authorized_wireless_network_path(network) : nil
    }
  end
end
