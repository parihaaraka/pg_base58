create or replace function decode_b58(src text)
returns bytea
language plpgsql immutable strict parallel safe cost 20
as
$$
declare
	mapBase58 int[] := '[50:123]={
		0,1,2,3,4,5,6,7,8,NULL,NULL,NULL,NULL,NULL,NULL,
		NULL,9,10,11,12,13,14,15,16,NULL,17,18,19,20,21,NULL,
		22,23,24,25,26,27,28,29,30,31,32,NULL,NULL,NULL,NULL,NULL,
		NULL,33,34,35,36,37,38,39,40,41,42,43,NULL,44,45,46,
		47,48,49,50,51,52,53,54,55,56,57}';
	src_array "char"[] := string_to_array(src, null);
	src_len int = cardinality(src_array);
	pos int := 1;
	length int := 0;
	zeroes int := 0;
	i int;
	ch int;
	space_chars int[] := array[9, 10, 13, 32];
	carry int;
	b256 bytea;  -- implementation with int[] is ~5% slower
	size int;
begin
	-- Translated with modifications from
	--   https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
	-- select convert_from(decode_b58('6et4bsKoqg5VTDir58dGARye9qbSivkGJbiX87LeXW4uuQ6hpjN9oAASZUBy2T9bydxKB1748tkpA'), 'UTF-8')

	-- Skip leading spaces.
	while src_array[pos]::int = any(space_chars) loop
		pos := pos + 1;
	end loop;

	-- Skip and count leading '1's.
	while src_array[pos] = '1' loop
		zeroes := zeroes + 1;
		pos := pos + 1;
	end loop;

	-- Destination buffer.
	size := (src_len - pos + 1) * 733 /1000 + 1 + zeroes; -- log(58) / log(256), rounded up
	b256 := '\x' || repeat('00', size);

	while pos <= src_len loop
		ch := src_array[pos]::int;
		if ch != all(space_chars) then
			carry := mapBase58[ch + 1];
			if carry is null then
				raise exception 'invalid b58 character code %', ch;
			end if;

			i := size - 1;
			while i >= 0 loop
				exit when carry = 0 and (size - 1 - i) >= length;
	         carry := carry + 58 * get_byte(b256, i);
	         b256  := set_byte(b256, i, carry & 255); -- %256 (not mandatory - set_byte() always use lower byte of 3-rd arg)
	         carry := carry >> 8; -- /256
	         i := i - 1;
			end loop;
			if carry != 0 then
				raise exception 'error b58 decoding: carry must be 0';
			end if;
			length := size - 1 - i;
		end if;

		pos := pos + 1;
	end loop;

	pos := 0;
	while pos < size and get_byte(b256, pos) = 0 loop
		pos := pos + 1;
	end loop;

	return substring(b256 from (pos - zeroes + 1));
end
$$;

create or replace function encode_b58(src bytea)
returns text
language plpgsql immutable strict parallel safe cost 20
as
$$
declare
	b58_digits "char"[] := '{1,2,3,4,5,6,7,8,9,A,B,C,D,E,F,G,H,J,K,L,M,N,P,Q,R,S,T,U,V,W,X,Y,Z,a,b,c,d,e,f,g,h,i,j,k,m,n,o,p,q,r,s,t,u,v,w,x,y,z}';
	src_len int := octet_length(src);
	length int := 0;
	zeroes int := 0;
	pos int := 0;
	size int;
	b58 int[];
	carry int;
	i int;
	res text;
begin
	-- Translated with modifications from
	--   https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp

	-- Skip & count leading zeroes.
	while get_byte(src, pos) = 0 loop
		pos := pos + 1;
		zeroes := zeroes + 1;
	end loop;

	-- Destination buffer size.
	size := (src_len - pos) * 138 / 100 + 1; -- log(256) / log(58), rounded up.

	while pos < src_len loop
		carry := get_byte(src, pos);
		i := size;
		while i > 0 loop
			exit when carry = 0 and (size - i) >= length;
         carry  := carry + coalesce(b58[i] << 8, 0); -- *256
         b58[i] := carry % 58;
         carry  := carry / 58;
         i := i - 1;
		end loop;
		if carry != 0 then
			raise exception 'error b58 encoding: carry must be 0';
		end if;
		length := size - i;

		pos := pos + 1;
	end loop;

	pos  := array_lower(b58, 1);
	size := array_upper(b58, 1);
	res  := repeat('1', zeroes);
	while pos <= size loop
		res := res || b58_digits[b58[pos] + 1];
		pos := pos + 1;
	end loop;

	return res;
end
$$;

create or replace function encode_b58_check(src bytea, ver int default 0)
returns text
language plpgsql immutable strict parallel safe
as
$$
declare
	_data_to_hash bytea := set_byte('\x00'::bytea, 0, ver) || src;
begin
	return encode_b58(_data_to_hash || substring(sha256(sha256(_data_to_hash)) for 4));
end
$$;

create or replace function decode_b58_check(in src text, out bin bytea, out ver int)
returns record
language plpgsql immutable strict parallel safe
as
$$
declare
	_data_with_hash bytea := decode_b58(src);
	_len int := octet_length(_data_with_hash);
	_hash bytea := substring(_data_with_hash from _len - 3);
begin
	if _hash != substring(sha256(sha256(substring(_data_with_hash from 1 for _len - 4))) for 4) then
		raise exception 'hash doesn''t match';
	end if;
	bin := substring(_data_with_hash from 2 for _len - 5);
	ver := get_byte(_data_with_hash, 0);
end
$$;

----------------------------------------
/*
do
$$
declare
	i int[];
	t1 timestamptz := clock_timestamp();
	src bytea := '\x0000'::bytea || convert_to('test', 'UTF-8') || '\x0000'::bytea;
begin
	--raise notice '%', src;
	for i in 1..50000 loop
		if decode_b58(encode_b58(src)) is distinct from src then
			raise exception 'err';
		end if;
	end loop;
	raise notice '%', clock_timestamp() - t1;
end
$$
*/