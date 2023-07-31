use nom::error::ParseError;

fn main() {
    println!("Hello, world!");
}

#[derive(Debug, PartialEq)]
enum Token<'a> {
    String(&'a [u8]),
    Semicolon,
    CommentStartHash,
    CommentContent(String),
}

type TokensList<'a> = std::vec::Vec<Token<'a>>;

#[derive(Debug)]
enum TokenizerError<'a> {
    InvalidInput(&'a [u8]),
}

fn parse_directive(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    nom::bytes::complete::take_while1(nom::character::is_alphabetic)(input)
}

fn parse_semicolon(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    if input.len() > 0 && input[0] == b';' {
        return Ok((&input[1..], &input[0..1]));
    }

    return Err(nom::Err::Failure(nom::error::make_error(
        input,
        nom::error::ErrorKind::Char,
    )));
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

fn tokenize_nginx_config(input: &[u8]) -> Result<TokensList, TokenizerError> {
    let mut input = input;
    let mut result: TokensList = vec![];

    while input.len() > 0 {
        println!("Parsing {}", std::str::from_utf8(input).unwrap());
        match parse_directive(input) {
            Ok((new_input, directive)) => {
                println!("Found  token {}", std::str::from_utf8(directive).unwrap());
                input = trim_left(new_input);
                result.push(Token::String(directive));
                continue;
            }
            Err(_) => {}
        }

        match parse_semicolon(input) {
            Ok((new_input, _)) => {
                println!("Found semicolon");
                input = trim_left(new_input);
                result.push(Token::Semicolon);
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
    #[test]
    fn tokenize_single_line() {
        use super::*;
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
}
