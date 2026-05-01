Rails.application.routes.draw do
  root "dashboard#index"
  get "/health", to: "health#show"
  get "/health/cards", to: "dashboard#cards"
  get "/health/sync_data", to: "health#sync_data"
  get "/health/sensors", to: "health#sensors"
  get "/health/nats_samples", to: "health#nats_samples"
  get "/health/recent_alerts", to: "health#recent_alerts"

  resources :audit_logs, only: %i[index show] do
    get :recent, on: :collection
    get :export, on: :collection
  end
  resources :backlog, only: :index do
    post :retry, on: :member
  end
  resources :audit_windows
  resources :authorized_wireless_networks
  resources :devices
  resources :identities, only: :index do
    get :inventory, on: :collection
    get :mac_summary, on: :collection
    get :distinct_values, on: :collection
  end
  resources :heatmap, only: :index
  resources :alerts, only: :index
  resources :shadow_it_alerts, only: :index do
    get :distinct_values, on: :collection
  end

  mount ActionCable.server => "/cable"
end
