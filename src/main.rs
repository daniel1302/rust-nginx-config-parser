use nom::{
    bytes::complete::{take_while, take_while1},
    character::{complete::digit1, is_digit},
    combinator::{consumed, opt, recognize},
    complete::tag,
    error::ParseError,
    sequence::tuple,
    IResult,
};

fn main() {
    println!("Hello, world!");
}

#[derive(Debug, PartialEq)]
enum Token<'a> {
    String(&'a [u8]),
    Int(i64),
    Semicolon,
    CommentStart,
    CommentLine(&'a [u8]),
    CurlyBracketLeft,
    CurlyBracketRight,
    Address(&'a [u8]),
}

type TokensList<'a> = std::vec::Vec<Token<'a>>;

#[derive(Debug)]
enum TokenizerError<'a> {
    InvalidInput(&'a [u8]),
    ParsingFailure(&'a [u8]),
}

fn parse_directive(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    nom::bytes::complete::is_not(" \t\n\r#;")(input)
}

fn parse_single_character(input: &[u8], ch: u8) -> nom::IResult<&[u8], &[u8]> {
    if input.len() > 0 && input[0] == ch {
        return Ok((&input[1..], &input[0..1]));
    }

    return Err(nom::Err::Failure(nom::error::make_error(
        input,
        nom::error::ErrorKind::Char,
    )));
}

fn parse_comment_line(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    nom::sequence::pair(
        nom::bytes::complete::tag("#"),
        nom::bytes::complete::is_not("\n\r"),
    )(input)
}

fn trim_left(input: &[u8]) -> &[u8] {
    for (idx, ch) in input.iter().enumerate() {
        match ch {
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => return &input[idx..],
        }
    }

    // nothing left to return
    return &[];
}

fn parse_address(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(tuple((
        digit1,
        nom::bytes::complete::tag("."),
        digit1,
        nom::bytes::complete::tag("."),
        digit1,
        nom::bytes::complete::tag("."),
        digit1,
        opt(recognize(tuple((nom::bytes::complete::tag(":"), digit1)))),
    )))(input)
}

fn parse_int(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_digit)(input)
}

fn tokenize_nginx_config(input: &[u8]) -> Result<TokensList, TokenizerError> {
    let mut input = input;
    let mut result: TokensList = vec![];

    while input.len() > 0 {
        println!("Parsing {}", std::str::from_utf8(input).unwrap());
        let input_trimmed = trim_left(input);

        match parse_address(input_trimmed) {
            Ok((new_input, address)) => {
                println!("found address");
                input = trim_left(new_input);
                result.push(Token::Address(address));
                continue;
            }
            Err(_) => {}
        }

        match parse_int(input_trimmed) {
            Ok((new_input, res)) => {
                println!("Found int {}", std::str::from_utf8(res).unwrap());
                input = trim_left(new_input);

                result.push(Token::Int(
                    std::str::from_utf8(res)
                        .unwrap()
                        .parse()
                        .or(Err(TokenizerError::ParsingFailure(res)))?,
                ));
                continue;
            }
            Err(_) => {}
        }

        match parse_single_character(input_trimmed, b';') {
            Ok((new_input, _)) => {
                println!("Found semicolon");
                input = trim_left(new_input);
                result.push(Token::Semicolon);
                continue;
            }
            Err(_) => {}
        }

        match parse_single_character(input_trimmed, b'{') {
            Ok((new_input, _)) => {
                println!("Found curly bracket left");
                input = trim_left(new_input);
                result.push(Token::CurlyBracketLeft);
                continue;
            }
            Err(_) => {}
        }

        match parse_single_character(input_trimmed, b'}') {
            Ok((new_input, _)) => {
                println!("Found curly bracket right");
                input = trim_left(new_input);
                result.push(Token::CurlyBracketRight);
                continue;
            }
            Err(_) => {}
        }

        match parse_directive(input_trimmed) {
            Ok((new_input, directive)) => {
                println!("Found string {}", std::str::from_utf8(directive).unwrap());
                input = trim_left(new_input);
                result.push(Token::String(directive));
                continue;
            }
            Err(_) => {}
        }

        match parse_comment_line(input) {
            Ok((new_input, (_, comment))) => {
                println!("Found comment line");
                input = trim_left(new_input);
                result.push(Token::CommentStart);
                result.push(Token::CommentLine(comment));
                continue;
            }
            Err(_) => {}
        }

        // no more input
        if trim_left(input).len() < 1 {
            break;
        }

        println!("TEST. {:?} ", trim_left(input));
        return Err(TokenizerError::InvalidInput(input));
    }

    return Ok(result);
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn tokenize_single_line() {
        const CONFIG: &str = r"user       www www;";
        let result = tokenize_nginx_config(CONFIG.as_bytes());
        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"user"),
                Token::String(b"www"),
                Token::String(b"www"),
                Token::Semicolon
            ]
        )
    }

    #[test]
    fn tokenize_comment() {
        const CONFIG: &str = r"worker_processes  5;  ## Default: 1";
        let result = tokenize_nginx_config(CONFIG.as_bytes());

        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"worker_processes"),
                Token::Int(5),
                Token::Semicolon,
                Token::CommentStart,
                Token::CommentLine(b"# Default: 1"),
            ]
        )
    }

    #[test]
    fn tokenize_address() {
        const CONFIG: &str = r###"address 127.0.0.1;
fastcgi_pass   127.0.0.1:1025;"###;
        let result = tokenize_nginx_config(CONFIG.as_bytes());
        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"address"),
                Token::Address(b"127.0.0.1"),
                Token::Semicolon,
                Token::String(b"fastcgi_pass"),
                Token::Address(b"127.0.0.1:1025"),
                Token::Semicolon,
            ]
        )
    }

    #[test]
    fn tokenize_multiline() {
        const CONFIG: &str = r###"user       www www;  ## Default: nobody
worker_processes  5;  ## Default: 1
worker_rlimit_nofile 8192;"###;

        let result = tokenize_nginx_config(CONFIG.as_bytes());
        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"user"),
                Token::String(b"www"),
                Token::String(b"www"),
                Token::Semicolon,
                Token::CommentStart,
                Token::CommentLine(b"# Default: nobody"),
                Token::String(b"worker_processes"),
                Token::Int(5),
                Token::Semicolon,
                Token::CommentStart,
                Token::CommentLine(b"# Default: 1"),
                Token::String(b"worker_rlimit_nofile"),
                Token::Int(8192),
                Token::Semicolon,
            ]
        )
    }

    #[test]
    fn tokenize_path() {
        const CONFIG: &str = r###"error_log  logs/error.log;
pid        logs/nginx.pid;
worker_rlimit_nofile 8192;"###;
        let result = tokenize_nginx_config(CONFIG.as_bytes());
        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"error_log"),
                Token::String(b"logs/error.log"),
                Token::Semicolon,
                Token::String(b"pid"),
                Token::String(b"logs/nginx.pid"),
                Token::Semicolon,
                Token::String(b"worker_rlimit_nofile"),
                Token::Int(8192),
                Token::Semicolon
            ],
        )
    }

    #[test]
    fn tokenize_context() {
        const CONFIG: &str = r###"events {
  worker_connections  4096;  ## Default: 1024
}"###;
        let result = tokenize_nginx_config(CONFIG.as_bytes());
        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"events"),
                Token::CurlyBracketLeft,
                Token::String(b"worker_connections"),
                Token::Int(4096),
                Token::Semicolon,
                Token::CommentStart,
                Token::CommentLine(b"# Default: 1024"),
                Token::CurlyBracketRight
            ]
        );
    }

    #[test]
    fn tokenize_nested_context() {
        const CONFIG: &str = r###"http {
  include    conf/mime.types;
  index    index.html index.htm index.php;

  server { # php/fastcgi
    listen       80;
    server_name  domain1.com www.domain1.com;
    access_log   logs/domain1.access.log  main;
    root         html;

    location ~ \.php$ {
      fastcgi_pass   127.0.0.1:1025;
    }
  }
}"###;
        let result = tokenize_nginx_config(CONFIG.as_bytes());
        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"http"),
                Token::CurlyBracketLeft,
                Token::String(b"include"),
                Token::String(b"conf/mime.types"),
                Token::Semicolon,
                Token::String(b"index"),
                Token::String(b"index.html"),
                Token::String(b"index.htm"),
                Token::String(b"index.php"),
                Token::Semicolon,
                Token::String(b"server"),
                Token::CurlyBracketLeft,
                Token::CommentStart,
                Token::CommentLine(b" php/fastcgi"),
                Token::String(b"listen"),
                Token::Int(80),
                Token::Semicolon,
                Token::String(b"server_name"),
                Token::String(b"domain1.com"),
                Token::String(b"www.domain1.com"),
                Token::Semicolon,
                Token::String(b"access_log"),
                Token::String(b"logs/domain1.access.log"),
                Token::String(b"main"),
                Token::Semicolon,
                Token::String(b"root"),
                Token::String(b"html"),
                Token::Semicolon,
                Token::String(b"location"),
                Token::String(b"~"),
                Token::String(b"\\.php$"),
                Token::CurlyBracketLeft,
                Token::String(b"fastcgi_pass"),
                Token::Address(b"127.0.0.1:1025"),
                Token::Semicolon,
                Token::CurlyBracketRight,
                Token::CurlyBracketRight,
                Token::CurlyBracketRight,
            ]
        )
    }

    #[test]
    fn tokenize_with_new_line_at_the_end() {
        const CONFIG: &str = r###"events {
  worker_connections  4096;  ## Default: 1024
}
   "###;
        let result = tokenize_nginx_config(CONFIG.as_bytes());
        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"events"),
                Token::CurlyBracketLeft,
                Token::String(b"worker_connections"),
                Token::Int(4096),
                Token::Semicolon,
                Token::CommentStart,
                Token::CommentLine(b"# Default: 1024"),
                Token::CurlyBracketRight
            ]
        );
    }

    #[test]
    fn tokenize_fastcgi() {
        const CONFIG: &str = r###"
        fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;
fastcgi_param  SERVER_NAME        $server_name;"###;

        let result = tokenize_nginx_config(CONFIG.as_bytes());

        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"fastcgi_param"),
                Token::String(b"SCRIPT_FILENAME"),
                Token::String(b"$document_root$fastcgi_script_name"),
                Token::Semicolon,
                Token::String(b"fastcgi_param"),
                Token::String(b"QUERY_STRING"),
                Token::String(b"$query_string"),
                Token::Semicolon,
                Token::String(b"fastcgi_param"),
                Token::String(b"REQUEST_METHOD"),
                Token::String(b"$request_method"),
                Token::Semicolon,
                Token::String(b"fastcgi_param"),
                Token::String(b"GATEWAY_INTERFACE"),
                Token::String(b"CGI/1.1"),
                Token::Semicolon,
                Token::String(b"fastcgi_param"),
                Token::String(b"SERVER_SOFTWARE"),
                Token::String(b"nginx/$nginx_version"),
                Token::Semicolon,
                Token::String(b"fastcgi_param"),
                Token::String(b"SERVER_NAME"),
                Token::String(b"$server_name"),
                Token::Semicolon,
            ]
        );
    }

    #[test]
    fn tokenize_mime_types() {
        const CONFIG: &str = r###"
types {
  text/html                             html htm shtml;
  text/css                              css;
  text/xml                              xml rss;
  image/gif                             gif;
  image/jpeg                            jpeg jpg;
  application/x-javascript              js;
  image/x-jng                           jng;
}"###;

        let result = tokenize_nginx_config(CONFIG.as_bytes());

        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"types"),
                Token::CurlyBracketLeft,
                Token::String(b"text/html"),
                Token::String(b"html"),
                Token::String(b"htm"),
                Token::String(b"shtml"),
                Token::Semicolon,
                Token::String(b"text/css"),
                Token::String(b"css"),
                Token::Semicolon,
                Token::String(b"text/xml"),
                Token::String(b"xml"),
                Token::String(b"rss"),
                Token::Semicolon,
                Token::String(b"image/gif"),
                Token::String(b"gif"),
                Token::Semicolon,
                Token::String(b"image/jpeg"),
                Token::String(b"jpeg"),
                Token::String(b"jpg"),
                Token::Semicolon,
                Token::String(b"application/x-javascript"),
                Token::String(b"js"),
                Token::Semicolon,
                Token::String(b"image/x-jng"),
                Token::String(b"jng"),
                Token::Semicolon,
                Token::CurlyBracketRight,
            ]
        );
    }

    #[test]
    fn tokenize_full_config() {
        const CONFIG: &str = r###"
user       www www;  ## Default: nobody
worker_processes  5;  ## Default: 1
error_log  logs/error.log;
pid        logs/nginx.pid;
worker_rlimit_nofile 8192;

events {
  worker_connections  4096;  ## Default: 1024
}

http {
  include    conf/mime.types;
  include    /etc/nginx/proxy.conf;
  include    /etc/nginx/fastcgi.conf;
  index    index.html index.htm index.php;
"###;
        let result = tokenize_nginx_config(CONFIG.as_bytes());
        assert_eq!(
            result.unwrap(),
            vec![
                Token::String(b"user"),
                Token::String(b"www"),
                Token::String(b"www"),
                Token::Semicolon,
                Token::CommentStart,
                Token::CommentLine(b"# Default: nobody"),
                Token::String(b"worker_processes"),
                Token::Int(5),
                Token::Semicolon,
                Token::CommentStart,
                Token::CommentLine(b"# Default: 1"),
                Token::String(b"error_log"),
                Token::String(b"logs/error.log"),
                Token::Semicolon,
                Token::String(b"pid"),
                Token::String(b"logs/nginx.pid"),
                Token::Semicolon,
                Token::String(b"worker_rlimit_nofile"),
                Token::Int(8192),
                Token::Semicolon,
                // Events context
                Token::String(b"events"),
                Token::CurlyBracketLeft,
                Token::String(b"worker_connections"),
                Token::Int(4096),
                Token::Semicolon,
                Token::CommentStart,
                Token::CommentLine(b"# Default: 1024"),
                Token::CurlyBracketRight,
                // HTTP context
                Token::String(b"http"),
                Token::CurlyBracketLeft,
                Token::String(b"include"),
                Token::String(b"conf/mime.types"),
                Token::Semicolon,
                Token::String(b"include"),
                Token::String(b"/etc/nginx/proxy.conf"),
                Token::Semicolon,
                Token::String(b"include"),
                Token::String(b"/etc/nginx/fastcgi.conf"),
                Token::Semicolon,
                Token::String(b"index"),
                Token::String(b"index.html"),
                Token::String(b"index.htm"),
                Token::String(b"index.php"),
                Token::Semicolon,
            ]
        );
    }
}
