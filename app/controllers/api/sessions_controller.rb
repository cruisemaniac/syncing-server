class Api::SessionsController < Api::ApiController
  respond_to :json

  before_action do
    if current_session.nil?
      render_unsupported_account_version
      return
    end
  end

  def active_sessions
    sessions = current_user.active_sessions
    sessions.each { |session| session[:current] = current_session.uuid == session.uuid }

    render json: sessions, status: :ok
  end

  def delete
    unless params[:uuid]
      render json: { error: { message: 'Please provide the session uuid.' } }, status: :bad_request
      return
    end

    if params[:uuid] == current_session.uuid
      render json: { error: { message: 'You can not delete your current session.' } }, status: :bad_request
      return
    end

    current_user.sessions.where(uuid: params[:uuid]).destroy

    render json: {}, status: :no_content
  end

  def delete_all
    current_user.sessions.where.not(uuid: current_session.uuid).destroy_all
    render json: {}, status: :no_content
  end

  def refresh
    unless params[:refresh_token]
      render json: {
        error: {
          message: 'Please provide the refresh token.',
        },
      }, status: :bad_request

      return
    end

    session = Sessions.where('uuid = ? AND refresh_token = ?', current_session.uuid, params[:refresh_token]).first

    if session.nil?
      render json: {
        error: {
          tag: 'invalid-refresh-token',
          message: 'The refresh token is not valid.',
        },
      }, status: :bad_request

      return
    end

    if session.is_expired?
      render json: {
        error: {
          tag: 'expired-refresh-token',
          message: 'The provided refresh token has expired.',
        },
      }, status: :unauthorized

      return
    end

    session.regenerate_tokens

    tokens = {
      access_token: {
        value: current_session.access_token,
        expiration: current_session.access_token_expire_at,
      },
      refresh_token: {
        value: current_session.refresh_token,
        expiration: current_session.refresh_token_expire_at,
      },
    }

    render json: tokens
  end

  private

  def render_unsupported_account_version
    render json: {
      error: {
        tag: 'unsupported-account-version',
        message: 'Account version not supported',
      },
    }, status: :bad_request
  end
end
