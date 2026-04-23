class ApplicationController < ActionController::Base
  include Paginatable
  include Sortable
end
