toc.dat                                                                                             0000600 0004000 0002000 00000011213 14647453070 0014447 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        PGDMP                       |            keycloak_db    16.3    16.3     �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false         �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false         �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false         �           1262    49676    keycloak_db    DATABASE     ~   CREATE DATABASE keycloak_db WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_India.1252';
    DROP DATABASE keycloak_db;
                postgres    false         �            1255    49688 G   fn_create_user(character varying, character varying, character varying)    FUNCTION     �  CREATE FUNCTION public.fn_create_user(_user_name character varying, _user_email character varying, _user_password character varying) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    new_user_id INTEGER;
BEGIN
    INSERT INTO public.users (user_name, user_email, user_password)
    VALUES (_user_name, _user_email, _user_password)
    RETURNING user_id INTO new_user_id;
    
    RETURN new_user_id;
END;
$$;
 �   DROP FUNCTION public.fn_create_user(_user_name character varying, _user_email character varying, _user_password character varying);
       public          postgres    false         �            1255    49694 .   fn_login(character varying, character varying)    FUNCTION     �  CREATE FUNCTION public.fn_login(_user_identifier character varying, _user_password character varying) RETURNS TABLE(user_id integer, user_name character varying, user_email character varying, user_password character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT u.user_id, u.user_name, u.user_email, u.user_password
    FROM public.users u
    WHERE (u.user_email = _user_identifier OR u.user_name = _user_identifier) AND u.user_password = _user_password;
END;
$$;
 e   DROP FUNCTION public.fn_login(_user_identifier character varying, _user_password character varying);
       public          postgres    false         �            1259    49678    users    TABLE     Z  CREATE TABLE public.users (
    user_id integer NOT NULL,
    user_name character varying(100) NOT NULL,
    user_email character varying(100) NOT NULL,
    user_password character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.users;
       public         heap    postgres    false         �            1259    49677    users_user_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.users_user_id_seq;
       public          postgres    false    216         �           0    0    users_user_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;
          public          postgres    false    215         R           2604    49681    users user_id    DEFAULT     n   ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);
 <   ALTER TABLE public.users ALTER COLUMN user_id DROP DEFAULT;
       public          postgres    false    215    216    216         �          0    49678    users 
   TABLE DATA           f   COPY public.users (user_id, user_name, user_email, user_password, created_at, updated_at) FROM stdin;
    public          postgres    false    216       4841.dat �           0    0    users_user_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.users_user_id_seq', 14, true);
          public          postgres    false    215         V           2606    49685    users users_pkey 
   CONSTRAINT     S   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    216         X           2606    49687    users users_user_email_key 
   CONSTRAINT     [   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_user_email_key UNIQUE (user_email);
 D   ALTER TABLE ONLY public.users DROP CONSTRAINT users_user_email_key;
       public            postgres    false    216                                                                                                                                                                                                                                                                                                                                                                                             4841.dat                                                                                            0000600 0004000 0002000 00000000700 14647453070 0014261 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        9	bhavy	bhavy@gmail.com	12345678	2024-07-18 18:16:12.164429	2024-07-18 18:16:12.164429
10	string	meet@gmail.com	12345678	2024-07-19 12:26:41.220829	2024-07-19 12:26:41.220829
11	johndoe	jd@gmail.com	12345678	2024-07-19 15:30:13.228597	2024-07-19 15:30:13.228597
12	hello	helloworld@gmail.com	12345678	2024-07-19 15:54:22.551733	2024-07-19 15:54:22.551733
13	monil	monil@gmail.com	12345678	2024-07-19 16:04:53.314853	2024-07-19 16:04:53.314853
\.


                                                                restore.sql                                                                                         0000600 0004000 0002000 00000011136 14647453070 0015400 0                                                                                                    ustar 00postgres                        postgres                        0000000 0000000                                                                                                                                                                        --
-- NOTE:
--
-- File paths need to be edited. Search for $$PATH$$ and
-- replace it with the path to the directory containing
-- the extracted data files.
--
--
-- PostgreSQL database dump
--

-- Dumped from database version 16.3
-- Dumped by pg_dump version 16.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

DROP DATABASE keycloak_db;
--
-- Name: keycloak_db; Type: DATABASE; Schema: -; Owner: postgres
--

CREATE DATABASE keycloak_db WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_India.1252';


ALTER DATABASE keycloak_db OWNER TO postgres;

\connect keycloak_db

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: fn_create_user(character varying, character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_create_user(_user_name character varying, _user_email character varying, _user_password character varying) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    new_user_id INTEGER;
BEGIN
    INSERT INTO public.users (user_name, user_email, user_password)
    VALUES (_user_name, _user_email, _user_password)
    RETURNING user_id INTO new_user_id;
    
    RETURN new_user_id;
END;
$$;


ALTER FUNCTION public.fn_create_user(_user_name character varying, _user_email character varying, _user_password character varying) OWNER TO postgres;

--
-- Name: fn_login(character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_login(_user_identifier character varying, _user_password character varying) RETURNS TABLE(user_id integer, user_name character varying, user_email character varying, user_password character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT u.user_id, u.user_name, u.user_email, u.user_password
    FROM public.users u
    WHERE (u.user_email = _user_identifier OR u.user_name = _user_identifier) AND u.user_password = _user_password;
END;
$$;


ALTER FUNCTION public.fn_login(_user_identifier character varying, _user_password character varying) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    user_id integer NOT NULL,
    user_name character varying(100) NOT NULL,
    user_email character varying(100) NOT NULL,
    user_password character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: users_user_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_user_id_seq OWNER TO postgres;

--
-- Name: users_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;


--
-- Name: users user_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users (user_id, user_name, user_email, user_password, created_at, updated_at) FROM stdin;
\.
COPY public.users (user_id, user_name, user_email, user_password, created_at, updated_at) FROM '$$PATH$$/4841.dat';

--
-- Name: users_user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.users_user_id_seq', 14, true);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: users users_user_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_user_email_key UNIQUE (user_email);


--
-- PostgreSQL database dump complete
--

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  