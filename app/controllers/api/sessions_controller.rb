class Api::SessionsController < Api::ApiController
  respond_to :json

  def active_sessions
    render json: {}, status: :ok
  end

  def delete
    render json: {}, status: :no_content
  end

  def delete_all
    render json: {}, status: :no_content
  end

  def refresh
    render json: {}, status: :ok
  end
end
