Rails.application.routes.draw do
  root "dashboard#index"

  resources :audit_logs, only: %i[index show] do
    get :recent, on: :collection
  end
  resources :backlog, only: :index do
    post :retry, on: :member
  end
  resources :audit_windows
  resources :identities, only: :index
  resources :heatmap, only: :index
  resources :alerts, only: :index

  mount ActionCable.server => "/cable"
end
