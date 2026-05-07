class IntegrationConfig < ApplicationRecord
  attribute :params, :json, default: -> { {} }
  encrypts :params

  has_many :integration_runs, dependent: :restrict_with_exception

  before_validation :normalize_slug
  before_validation :normalize_types
  before_validation :assign_param_schema
  before_validation :normalize_params

  validates :name, :slug, :source_type, :destination_type, presence: true
  validates :slug, uniqueness: true, format: { with: /\A[a-z0-9-]+\z/ }
  validates :source_type, :destination_type, inclusion: { in: IntegrationParamSchema.types }
  validate :params_match_schema

  scope :enabled, -> { where(enabled: true) }
  scope :by_slug, ->(slug) { where(slug: slug) }
  scope :ordered, -> { order(enabled: :desc, name: :asc) }

  def masked_params
    IntegrationParamSchema.masked_params(source_type, params)
  end

  def combined_params(overrides = {})
    params.to_h.merge(overrides.to_h.reject { |_, value| value.nil? })
  end

  private

  def normalize_slug
    self.slug = name.to_s.parameterize if slug.blank? && name.present?
    self.slug = slug.to_s.strip.downcase.presence
  end

  def normalize_types
    self.source_type = source_type.to_s.strip.downcase.presence
    self.destination_type = destination_type.to_s.strip.downcase.presence
    self.stream_name = stream_name.to_s.strip.presence
    self.cursor_field = cursor_field.to_s.strip.presence
    self.schedule_cron = schedule_cron.to_s.strip.presence
  end

  def assign_param_schema
    self.param_schema = IntegrationParamSchema.schema_for(source_type)
  end

  def normalize_params
    self.params = params.to_h.transform_keys(&:to_s)
  end

  def params_match_schema
    schema = IntegrationParamSchema.schema_for(source_type)
    return if schema.blank?

    current_params = params.to_h
    schema.each do |field_key, field|
      next unless field["required"]

      errors.add(:params, "#{field_key} is required for #{source_type}") if absent_param_value?(current_params[field_key])
    end

    params.to_h.each do |key, value|
      field = schema[key.to_s]
      if field.blank?
        errors.add(:params, "#{key} is not supported for #{source_type}")
        next
      end

      validate_param_type(key, value, field)
    end
  end

  def validate_param_type(key, value, field)
    return if absent_param_value?(value)

    case field["type"]
    when "integer"
      validate_integer_param(key, value)
    when "select"
      errors.add(:params, "#{key} must be one of #{Array(field["options"]).join(", ")}") unless Array(field["options"]).include?(value)
    when "boolean"
      errors.add(:params, "#{key} must be true or false") unless [true, false, "true", "false", "1", "0", 1, 0].include?(value)
    end
  end

  def validate_integer_param(key, value)
    Integer(value)
  rescue ArgumentError, TypeError
    errors.add(:params, "#{key} must be an integer")
  end

  def absent_param_value?(value)
    value.nil? || (value.respond_to?(:empty?) && value.empty?)
  end
end
