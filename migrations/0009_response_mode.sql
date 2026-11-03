ALTER TABLE authorization_requests ADD COLUMN response_mode text NOT NULL DEFAULT 'query'
    CHECK (response_mode IN ('query', 'fragment', 'form_post'));
