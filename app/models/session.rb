class Session < ApplicationRecord
  validates :user_agent, length: { in: 0..255, allow_nil: true }
  validates :api_version, inclusion: { in: %w(20200115) }

  has_secure_token :access_token
  has_secure_token :refresh_token

  before_create :set_expire_at

  def serializable_hash(options = {})
    allowed_options = [
      'uuid',
      'user_agent',
      'api_version',
      'created_at',
      'updated_at',
    ]

    super(options.merge(only: allowed_options))
  end

  def access_token_expire_at
    expire_at - refresh_token_expiration_time + access_token_expiration_time
  end

  def refresh_token_expire_at
    expire_at
  end

  def regenerate_tokens
    regenerate_access_token
    regenerate_refresh_token
    set_expire_at
  end

  def is_expired?
    expire_at < DateTime.now
  end

  private

  def config
    Rails.application.config.x.session
  end

  def refresh_token_expiration_time
    config[:refresh_token_expiration_time].seconds
  end

  def access_token_expiration_time
    config[:access_token_expiration_time].seconds
  end

  def set_expire_at
    self.expire_at = DateTime.now + refresh_token_expiration_time
  end
end
