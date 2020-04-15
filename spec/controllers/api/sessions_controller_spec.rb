require 'rails_helper'

RSpec.describe Api::SessionsController, type: :controller do
  test_password = '123456'

  let(:test_user) do
    create(:user, password: test_password, version: '004')
  end

  let(:test_user_credentials) do
    { email: test_user.email, password: test_password }
  end

  describe 'GET sessions/active' do
    context 'when not signed in' do
      it 'should return unauthorized error' do
        get :active_sessions

        expect(response).to have_http_status(:unauthorized)
        expect(response.headers['Content-Type']).to eq('application/json; charset=utf-8')

        parsed_response_body = JSON.parse(response.body)

        expect(parsed_response_body).to_not be_nil
        expect(parsed_response_body['error']).to_not be_nil
        expect(parsed_response_body['error']['message']).to eq('Invalid login credentials.')
        expect(parsed_response_body['error']['tag']).to eq('invalid-auth')
      end
    end

    context 'when signed in' do
      context 'and user has an account version < 004' do
        it 'should return unsupported error' do
          get :active_sessions
  
          expect(response).to have_http_status(:bad_request)
          expect(response.headers['Content-Type']).to eq('application/json; charset=utf-8')
  
          parsed_response_body = JSON.parse(response.body)
  
          expect(parsed_response_body).to_not be_nil
          expect(parsed_response_body['error']).to_not be_nil
          expect(parsed_response_body['error']['message']).to eq('Account version not supported.')
          expect(parsed_response_body['error']['tag']).to eq('unsupported-account-version')
        end
      end
    end
  end
end
