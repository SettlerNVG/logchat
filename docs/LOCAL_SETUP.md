# Локальная установка и тестирование LogChat

## Статус проекта

| Компонент | Статус | Описание |
|-----------|--------|----------|
| Proto файлы | ✅ | gRPC сервисы (auth, user, session, chat) |
| Proto генерация | ✅ | Go код сгенерирован в proto/gen/ |
| БД миграции | ✅ | PostgreSQL схема |
| Server код | ✅ | Auth, Users, Sessions handlers |
| Client код | ✅ | Crypto, P2P, TUI |
| Docker | ✅ | Compose для БД и сервера |
| Unit тесты | ✅ | Crypto и auth тесты проходят |
| CI/CD | ✅ | GitHub Actions workflows |

## Быстрый старт (локально)

### 1. Запустить PostgreSQL

```bash
cd logmessager

# Запустить только БД
docker-compose -f docker/docker-compose.yml up -d postgres

# Подождать пока запустится
docker-compose -f docker/docker-compose.yml logs -f postgres
# Ctrl+C когда увидишь "database system is ready to accept connections"

# Применить миграции
docker-compose -f docker/docker-compose.yml up migrate
```

### 2. Создать .env файл

```bash
cp .env.example .env
```

Отредактируй `.env`:
```env
DATABASE_URL=postgres://logmessager:logmessager@localhost:5432/logmessager?sslmode=disable
JWT_SECRET=my-super-secret-key-for-development
```

### 3. Запустить сервер

```bash
cd server
go run ./cmd
```

Должен увидеть:
```
INF Starting LogChat server env=development port=50051
INF Connected to database
INF gRPC server listening addr=0.0.0.0:50051
```

### 4. Запустить клиент (в другом терминале)

```bash
cd client
go run ./cmd
```

## Тестирование

### Unit тесты

```bash
# Тесты сервера
cd server && go test ./... -v

# Тесты клиента (crypto)
cd client && go test ./... -v
```

### Проверка БД

```bash
# Подключиться к БД
docker exec -it logmessager-db psql -U logmessager -d logmessager

# Посмотреть таблицы
\dt

# Посмотреть пользователей
SELECT * FROM users;

# Выйти
\q
```

## Залить на GitHub

### 1. Создать репозиторий

1. Зайди на github.com
2. New repository → `logmessager`
3. НЕ добавляй README (у нас уже есть)

### 2. Инициализировать git

```bash
cd logmessager

# Создать .gitignore
cat > .gitignore << 'EOF'
# Binaries
bin/
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary
*.test

# Output of go coverage
*.out

# Dependency directories
vendor/

# IDE
.idea/
.vscode/
*.swp
*.swo

# Environment
.env
.env.local
.env.prod

# Generated proto (если будешь генерировать)
proto/gen/

# OS
.DS_Store
Thumbs.db

# Logs
*.log
/tmp/

# Keys and certs
*.pem
*.key
*.crt
docker/certs/
EOF

# Инициализировать репозиторий
git init
git add .
git commit -m "Initial commit: LogMessager MVP"

# Подключить remote
git remote add origin https://github.com/YOUR_USERNAME/logmessager.git
git branch -M main
git push -u origin main
```

## Структура проекта

```
logmessager/
├── client/                 # Клиент
│   ├── cmd/main.go        # Entry point
│   └── internal/
│       ├── client/        # Основная логика
│       ├── config/        # Конфигурация
│       ├── crypto/        # E2EE (Curve25519, AES-GCM)
│       ├── p2p/           # Host/Client режимы
│       ├── storage/       # Локальное хранение
│       └── tui/           # Terminal UI
├── server/                 # Сервер
│   ├── cmd/main.go        # Entry point
│   ├── internal/
│   │   ├── auth/          # JWT, bcrypt
│   │   ├── config/        # Конфигурация
│   │   ├── grpc/          # Handlers
│   │   ├── repository/    # PostgreSQL
│   │   └── service/       # Бизнес-логика
│   └── migrations/        # SQL миграции
├── proto/                  # gRPC определения
├── docker/                 # Docker конфиги
├── scripts/               # Скрипты сборки
└── docs/                  # Документация
```

## Следующие шаги

1. **E2E тесты** — написать интеграционные тесты
2. **TLS** — добавить поддержку TLS для production
3. **Релиз** — собрать бинарники для разных платформ

## Troubleshooting

### "database connection refused"

БД не запущена:
```bash
docker-compose -f docker/docker-compose.yml up -d postgres
```

### "port 50051 already in use"

Убить процесс:
```bash
lsof -i :50051
kill -9 <PID>
```

### "go: module not found"

```bash
cd server && go mod tidy
cd ../client && go mod tidy
```
