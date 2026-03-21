-- Warta Database Schema
-- Run order matters — this is the single init file

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    TEXT UNIQUE NOT NULL CHECK (length(username) BETWEEN 2 AND 32),
    email       TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    bio         TEXT DEFAULT '',
    avatar_path TEXT DEFAULT '',
    is_admin    BOOLEAN NOT NULL DEFAULT FALSE,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    theme_pref  TEXT NOT NULL DEFAULT 'auto' CHECK (theme_pref IN ('auto', 'light', 'dark')),
    -- E2EE: store user's public key (base64 encoded)
    public_key  TEXT DEFAULT '',
    storage_used_bytes BIGINT NOT NULL DEFAULT 0,
    storage_limit_bytes BIGINT NOT NULL DEFAULT 1073741824, -- 1024 MB
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- INVITES
-- ─────────────────────────────────────────
CREATE TABLE invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        TEXT UNIQUE NOT NULL DEFAULT encode(gen_random_bytes(12), 'hex'),
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_by     UUID REFERENCES users(id),
    max_uses    INT NOT NULL DEFAULT 1,
    use_count   INT NOT NULL DEFAULT 0,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- POSTS (microblog + longform)
-- ─────────────────────────────────────────
CREATE TABLE posts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    author_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- micro: short text (≤280 chars). longform: full markdown
    post_type       TEXT NOT NULL DEFAULT 'micro' CHECK (post_type IN ('micro', 'longform')),
    content         TEXT NOT NULL CHECK (length(content) <= 40000),
    -- if longform: title shown
    title           TEXT DEFAULT '',
    -- parent post for longform expansion of a micro post
    parent_id       UUID REFERENCES posts(id) ON DELETE SET NULL,
    is_removed      BOOLEAN NOT NULL DEFAULT FALSE,
    removed_by      UUID REFERENCES users(id),
    removed_at      TIMESTAMPTZ,
    removal_reason  TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_posts_author ON posts(author_id);
CREATE INDEX idx_posts_created ON posts(created_at DESC);
CREATE INDEX idx_posts_parent ON posts(parent_id);

-- ─────────────────────────────────────────
-- MEDIA ATTACHMENTS
-- ─────────────────────────────────────────
CREATE TABLE media (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id         UUID REFERENCES posts(id) ON DELETE CASCADE,
    -- null post_id = avatar or other user media
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    media_type      TEXT NOT NULL CHECK (media_type IN ('image', 'audio', 'video')),
    filename        TEXT NOT NULL,
    storage_path    TEXT NOT NULL,
    mime_type       TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    -- duration in seconds for audio/video
    duration_secs   INT,
    width           INT,
    height          INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_media_post ON media(post_id);
CREATE INDEX idx_media_user ON media(user_id);

-- ─────────────────────────────────────────
-- REACTIONS (thumbs up)
-- ─────────────────────────────────────────
CREATE TABLE reactions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id     UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(post_id, user_id)
);

CREATE INDEX idx_reactions_post ON reactions(post_id);

-- ─────────────────────────────────────────
-- COMMENTS
-- ─────────────────────────────────────────
CREATE TABLE comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id     UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    author_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content     TEXT NOT NULL CHECK (length(content) BETWEEN 1 AND 2000),
    parent_comment_id UUID REFERENCES comments(id) ON DELETE CASCADE,
    is_removed  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_comments_post ON comments(post_id);
CREATE INDEX idx_comments_author ON comments(author_id);

-- ─────────────────────────────────────────
-- MODERATION VOTES (decentralised, 2/3 majority)
-- ─────────────────────────────────────────
CREATE TABLE mod_votes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- can vote on posts or comments
    target_type TEXT NOT NULL CHECK (target_type IN ('post', 'comment')),
    target_id   UUID NOT NULL,
    voter_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vote        TEXT NOT NULL CHECK (vote IN ('remove', 'keep')),
    reason      TEXT DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(target_type, target_id, voter_id)
);

CREATE INDEX idx_mod_votes_target ON mod_votes(target_type, target_id);

-- ─────────────────────────────────────────
-- DIRECT MESSAGES (E2EE)
-- Server only stores encrypted ciphertext
-- ─────────────────────────────────────────
CREATE TABLE messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- ciphertext encrypted with recipient's public key (base64)
    ciphertext      TEXT NOT NULL,
    -- ephemeral sender public key used for this message (ECDH)
    ephemeral_pubkey TEXT NOT NULL,
    -- nonce/IV used for encryption (base64)
    nonce           TEXT NOT NULL,
    is_read         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_messages_recipient ON messages(recipient_id, created_at DESC);
CREATE INDEX idx_messages_sender ON messages(sender_id, created_at DESC);
CREATE INDEX idx_messages_conversation ON messages(
    LEAST(sender_id, recipient_id),
    GREATEST(sender_id, recipient_id),
    created_at DESC
);

-- ─────────────────────────────────────────
-- SESSIONS
-- ─────────────────────────────────────────
CREATE TABLE sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT UNIQUE NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(token_hash);

-- ─────────────────────────────────────────
-- SEED: first admin user placeholder
-- Actual password set via setup script
-- ─────────────────────────────────────────
-- Admin is created via POST /api/setup on first run
-- once done, the endpoint is disabled permanently
CREATE TABLE setup_state (
    id          INT PRIMARY KEY DEFAULT 1,
    completed   BOOLEAN NOT NULL DEFAULT FALSE,
    completed_at TIMESTAMPTZ
);
INSERT INTO setup_state VALUES (1, FALSE, NULL);
