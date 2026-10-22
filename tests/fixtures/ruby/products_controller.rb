class ProductsController < ApplicationController
  def search
    term = params[:q]
    # SQL injection: the fragment is built from the request parameter
    @products = Product.where("name LIKE '%#{term}%'")
    render :search
  end

  def download
    name = params[:file]
    # Path traversal
    send_file("/var/data/#{name}")
  end

  def run
    host = params[:host]
    # Command injection
    system("ping -c 1 #{host}")
  end

  def greet
    # XSS: the value is rendered without escaping
    render html: "<h1>Hello #{params[:name]}</h1>".html_safe
  end
end
