Rails.application.routes.draw do
  root "dashboard#index"
  get "/health", to: "health#show"

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
  end
  resources :heatmap, only: :index
  resources :alerts, only: :index
  resources :shadow_it_alerts, only: :index

  mount ActionCable.server => "/cable"
end
