class DevicesController < ApplicationController
  SORTS = {
    "display_name" => :display_name,
    "username" => :username,
    "hostname" => :hostname,
    "os_hint" => :os_hint,
    "mac_hint" => :mac_hint,
    "last_seen" => :last_seen
  }.freeze

  FILTERS = {
    "display_name" => :display_name,
    "username" => :username,
    "hostname" => :hostname,
    "os_hint" => :os_hint,
    "mac_hint" => :mac_hint,
    "last_seen" => { column: :last_seen, type: :date }
  }.freeze

  def index
    @query = params[:q].to_s.strip
    @devices = Device.search(@query)
    @devices = apply_grid_filters(@devices, FILTERS)
    @devices = apply_sort(@devices, SORTS, default_sort: :display_name, default_direction: :asc)
    @devices = paginate(@devices)
    @device_page_payload = device_page_payload(rows: @devices, mode: "index")

    respond_to do |format|
      format.html
      format.json { render json: @device_page_payload }
    end
  end

  def new
    @device = Device.new
    @device_page_payload = device_page_payload(rows: [], mode: "form", device: @device)
  end

  def create
    @device = Device.new(device_params)
    if @device.save
      respond_to do |format|
        format.html { redirect_to devices_path, notice: "MAC identifier saved", status: :see_other }
        format.json { render json: { device: device_payload(@device), redirectUrl: devices_path }, status: :created }
      end
    else
      render_device_errors(:new)
    end
  end

  def edit
    @device = Device.find(params[:id])
    @device_page_payload = device_page_payload(rows: [], mode: "form", device: @device)
  end

  def update
    @device = Device.find(params[:id])
    if @device.update(device_params)
      respond_to do |format|
        format.html { redirect_to devices_path, notice: "MAC identifier updated", status: :see_other }
        format.json { render json: { device: device_payload(@device), redirectUrl: devices_path } }
      end
    else
      render_device_errors(:edit)
    end
  end

  def destroy
    Device.find(params[:id]).destroy!
    respond_to do |format|
      format.html { redirect_to devices_path, notice: "MAC identifier removed", status: :see_other }
      format.json { head :no_content }
    end
  end

  private

  def device_params
    params.require(:device).permit(:display_name, :username, :hostname, :os_hint, :mac_hint, :notes)
  end

  def render_device_errors(template)
    @device_page_payload = device_page_payload(rows: [], mode: "form", device: @device)
    respond_to do |format|
      format.html { render template, status: :unprocessable_entity }
      format.json { render json: { errors: @device.errors.full_messages, device: device_payload(@device) }, status: :unprocessable_entity }
    end
  end

  def device_page_payload(rows:, mode:, device: nil)
    {
      mode: mode,
      rows: rows.map { |row| device_payload(row) },
      current: device && device_payload(device),
      errors: device&.errors&.full_messages || [],
      totalCount: @total_count || rows.length,
      totalPages: @total_pages || 1,
      currentPage: @current_page || 1,
      perPage: @per_page || 50,
      sortKey: @sort || "display_name",
      sortDirection: @direction || "asc",
      query: @query || "",
      filters: parsed_grid_filters,
      endpoints: {
        index: devices_path,
        create: devices_path
      }
    }
  end

  def device_payload(device)
    {
      id: device.mac_id,
      mac_id: device.mac_id,
      device_id: device.device_id,
      display_name: device.display_name,
      username: device.username,
      hostname: device.hostname,
      os_hint: device.os_hint,
      mac_hint: device.mac_hint,
      notes: device.notes,
      first_seen: device.first_seen&.iso8601,
      last_seen: device.last_seen&.iso8601,
      edit_url: device.persisted? ? edit_device_path(device) : nil,
      update_url: device.persisted? ? device_path(device) : nil,
      delete_url: device.persisted? ? device_path(device) : nil
    }
  end
end
