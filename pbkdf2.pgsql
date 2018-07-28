-- PostgreSQL functions for PBKDF2
-- inspired by (and in large parts copied from):
-- https://stackoverflow.com/questions/47162200/pbkdf2-function-in-postgresql


-- SCHEMA pbkdf2
DO $$
BEGIN
    IF NOT EXISTS (SELECT schema_name FROM information_schema.schemata
                   WHERE schema_name = 'pbkdf2') THEN
        EXECUTE 'CREATE SCHEMA pbkdf2';
    END IF;
END
$$;

-- FUNCTION pbkdf2.pbkdf2_hmac
CREATE OR REPLACE FUNCTION pbkdf2.pbkdf2_hmac
        (password bytea,
         salt bytea,
         iterations integer,
         hash_name text,
         dklen integer DEFAULT NULL)
    RETURNS bytea
    IMMUTABLE
    LANGUAGE 'plpgsql'
AS $$
DECLARE 
    hash_length integer;
    block_count integer;
    output bytea;
    the_last bytea;
    xorsum bytea;
    i_as_int32 bytea;
    i integer;
    j integer;
    k integer;
BEGIN
    CASE hash_name
        WHEN 'md5' THEN
            hash_length := 16;
        WHEN 'sha1' THEN
            hash_length := 20;
        WHEN 'sha256' THEN
            hash_length := 32;
        WHEN 'sha512' THEN
            hash_length := 64;
        ELSE
            RAISE EXCEPTION 'Unknown algorithm "%"', algorithm;
    END CASE;

    IF dklen IS NULL THEN
        dklen := hash_length;
        block_count := 1;
    ELSE
        block_count := ceil(dklen::real / hash_length::real);
    END IF;

    output := '';

    FOR i IN 1 .. block_count LOOP
        i_as_int32 := E'\\000\\000\\000'::bytea || chr(i)::bytea;
        i_as_int32 := substring(i_as_int32, length(i_as_int32) - 3);

        the_last := salt::bytea || i_as_int32;

        xorsum := pgcrypto.hmac(the_last, password, hash_name);
        the_last := xorsum;

        FOR j IN 2 .. iterations LOOP
            the_last := pgcrypto.hmac(the_last, password, hash_name);

            --
            -- xor the two
            --
            FOR k IN 1 .. length(xorsum) LOOP
                xorsum := set_byte(xorsum, k - 1, get_byte(xorsum, k - 1) # get_byte(the_last, k - 1));
            END LOOP;
        END LOOP;

        output := output || xorsum;
    END LOOP;

    RETURN substring(output FROM 1 FOR dklen);
END;
$$;

-- FUNCTION pbkdf2.hash
CREATE OR REPLACE FUNCTION pbkdf2.hash
        (password text,
         salt bytea DEFAULT NULL,
         hash_name text DEFAULT 'sha256',
         iterations integer DEFAULT 150000,
         salt_length integer DEFAULT 18,
         dklen integer DEFAULT NULL)
    RETURNS text
    IMMUTABLE
    LANGUAGE 'plpgsql'
AS $$
BEGIN
    IF salt IS NULL THEN
        salt := substring(
                    encode(
                        pgcrypto.gen_random_bytes(ceil(salt_length::real / 2)::integer),
                        'HEX')
                FROM 1 FOR salt_length);
    END IF;

    RETURN 'pbkdf2_' || hash_name ||
           '$' || iterations ||
           '$' || convert_from(salt, 'latin1') ||
           '$' || encode(pbkdf2.pbkdf2_hmac(password::bytea, salt, iterations, hash_name, dklen), 'BASE64');
END;
$$;

-- FUNCTION pbkdf2.verify
CREATE OR REPLACE FUNCTION pbkdf2.verify(password text, combined text)
    RETURNS boolean
    IMMUTABLE
    LANGUAGE 'plpgsql'
AS $$
DECLARE 
    hash bytea;
BEGIN
    hash := decode(split_part(combined, '$', 4), 'BASE64');

    RETURN hash = pbkdf2.pbkdf2_hmac(
                      password::bytea,
                      split_part(combined, '$', 3)::bytea,
                      split_part(combined, '$', 2)::integer,
                      split_part(split_part(combined, '$', 1), '_', 2),
                      length(hash));
END;
$$;
