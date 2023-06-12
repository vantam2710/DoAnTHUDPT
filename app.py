from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pymysql.cursors

app = Flask(__name__)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Thiết lập kết nối tới MySQL
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='',
    db='udpt_g8',
    charset='utf8mb4',
    cursorclass=pymysql.cursors.DictCursor
)

# đăng ký tài khoản
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        with connection.cursor() as cursor:
            # Kiểm tra xem tên người dùng đã tồn tại trong cơ sở dữ liệu chưa
            sql = "SELECT * FROM nguoidung WHERE username=%s"
            cursor.execute(sql, (username,))
            result = cursor.fetchone()
            if result:
                return jsonify({'message': 'Tên người dùng đã tồn tại'})

            # INSERT dữ liệu để đăng ký tài khoản mới
            sql = "INSERT INTO nguoidung (username, password) VALUES (%s, %s)"
            cursor.execute(sql, (username, hashed_password))
            connection.commit()

        return jsonify({'message': 'Đăng ký thành công'})
    except Exception as e:
        return jsonify({'message': str(e)})
    finally:
        connection.close()

# đăng nhập
@app.route('/login', methods=['POST'])
def login():
    try:

        data = request.get_json()
        username = data['username']
        password = data['password']

        with connection.cursor() as cursor:
            # Lấy thông tin người dùng từ CSDL
            sql = "SELECT * FROM nguoidung WHERE username=%s"
            cursor.execute(sql, (username,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'message': 'Người dùng không tồn tại'})

            # Kiểm tra mật khẩu hợp lệ
            if bcrypt.check_password_hash(user['password'], password):
                # Tạo JWT token
                access_token = create_access_token(identity=username)
                return jsonify({'access_token': access_token})

            return jsonify({'message': 'Mật khẩu không đúng'})
    except Exception as e:
        return jsonify({'message': str(e)})
    finally:
        connection.close()

# đổi mật khẩu
@app.route('/changepassword', methods=['POST'])
@jwt_required()
def change_password():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        new_password = data['new_password']

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        with connection.cursor() as cursor:
            # UPDATE để cập nhật mật khẩu mới
            sql = "UPDATE nguoidung SET password=%s WHERE username=%s"
            cursor.execute(sql, (hashed_password, current_user))
            connection.commit()

        return jsonify({'message': 'Đổi mật khẩu thành công'})
    except Exception as e:
        return jsonify({'message': str(e)})
    finally:
        connection.close()

if __name__ == '__main__':
    app.run()