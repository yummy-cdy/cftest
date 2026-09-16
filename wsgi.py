from app import app, init_db

# gunicorn --preload로 마스터 프로세스가 모듈을 한 번만 임포트할 때 실행되므로,
# 워커마다 중복 초기화(및 admin 계정 UNIQUE 제약 충돌)가 발생하지 않는다.
init_db()

if __name__ == "__main__":
    app.run()
