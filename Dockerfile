FROM python:3.12-slim
WORKDIR /app
# gosu: 컨테이너를 root로 시작해 볼륨 권한을 맞춘 뒤, 실제 앱 프로세스는 비root 계정으로
# 넘기기(privilege drop) 위해 사용한다.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# 이미지를 새로 빌드할 때마다(코드가 바뀔 때마다 COPY 레이어 캐시가 깨지므로) 갱신되는
# 빌드 시각을 남긴다. 배포가 실제로 서버에 반영됐는지 페이지 하단에서 눈으로 확인하기 위함.
RUN date -u +"%Y-%m-%d %H:%M UTC" > BUILD_INFO
ENV PORT=8000
ENV CF_DATA_DIR=/app/data
# 컨테이너를 root가 아닌 전용 계정으로 실행해, 앱이 침해되더라도 피해 범위를 제한한다.
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app \
    && chmod +x docker-entrypoint.sh
EXPOSE 8000
# 개발 서버(werkzeug) 대신 프로덕션급 WSGI 서버(gunicorn)로 구동한다(진입점 스크립트 참고).
ENTRYPOINT ["./docker-entrypoint.sh"]
