class UsersController < ApplicationController
  before_action :require_logged_in, only: [:index, :show, :edit, :update]
  before_action :require_logged_out, only: [:new, :create]  

  def new
    render :new
  end

  def create
    @user = User.new(user_params)

    if @user.save
      login(@user)
      redirect_to cats_url
    else
      render json: @user.errors.full_messages, status: :unprocessable_entity
    end
    
  end

  private
  def user_params
    params.require(:user).permit(:username, :password)
  end
end