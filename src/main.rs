use nom::{
    bytes::complete::{take_while, take_while1},
    character::is_digit,
    error::ParseError,
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

    return input;
}

fn parse_address(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_digit)(input)
}

fn parse_int(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_digit)(input)
}

fn tokenize_nginx_config(input: &[u8]) -> Result<TokensList, TokenizerError> {
    let mut input = input;
    let mut result: TokensList = vec![];

    while input.len() > 0 {
        println!("Parsing {}", std::str::from_utf8(input).unwrap());

        match parse_int(input) {
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

        match parse_single_character(input, b';') {
            Ok((new_input, _)) => {
                println!("Found semicolon");
                input = trim_left(new_input);
                result.push(Token::Semicolon);
                continue;
            }
            Err(_) => {}
        }

        match parse_single_character(input, b'{') {
            Ok((new_input, _)) => {
                println!("Found curly bracket left");
                input = trim_left(new_input);
                result.push(Token::CurlyBracketLeft);
                continue;
            }
            Err(_) => {}
        }

        match parse_single_character(input, b'}') {
            Ok((new_input, _)) => {
                println!("Found curly bracket right");
                input = trim_left(new_input);
                result.push(Token::CurlyBracketRight);
                continue;
            }
            Err(_) => {}
        }

        match parse_directive(input) {
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

        return Err(TokenizerError::InvalidInput(input));
    }

    return Ok(result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
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
                Token::String(b"127.0.0.1:1025"),
                Token::Semicolon,
                Token::CurlyBracketRight,
                Token::CurlyBracketRight,
                Token::CurlyBracketRight,
            ]
        )
    }
}
