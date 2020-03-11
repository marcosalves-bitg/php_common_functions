<?php
/**
 * created @ 11/03/2020
 * created by marcosalves-bitg - https://github.com/marcosalves-bitg
 * with help from danpedron (dantipmjs) - https://github.com/dantipmjs
 */

// Vai receber uma valor ($dados) e assinar essa informação, retornando a própria assinatura.
function assinar($dados)
{
    // Pega a chave privada, fornecida por quem gerou as informações.
    $key = openssl_pkey_get_private("file://./keys/chave_privada.pem");
    // Assina os $dados, salvando em $signature utilizando a chave
    $ok=openssl_sign($dados,$signature,$key);
    if ($ok == 1)
    {
        // Retorna a assinatura codificada em base64
        $sig=base64_encode($signature);
    }
    else
    {
        $sig=null;
    }
    // Se foi possível assinar, retorna o texto assinado e codificado em base64; Se não, retorna NULL
    return $sig;
}

// Vai receber o texto original e a hash gerada pela assinatura. Decodifica a assinatura de bas64. Verifica se o texto assinado ($assinatura) bate com o texto enviado ($text)
function verifica($text,$assinatura)
{
    //Pega a chave publica, fornecida por quem gerou as informações
    if($key = openssl_pkey_get_public("file://./keys/chave_publica.pem"))
    {
        // decodifica de base64 a assinatura passada como parâmetro
        $signature = base64_decode($assinatura);
        // Vai verificar se o texto assinado coincide com o texto repassado como parâmetro
        $ok=openssl_verify($text,$signature,$key);
        openssl_free_key($key);
        if ($ok == 1)
        {
            $retorno=true;
        }
        else
        {
            $retorno=false;
        }
    }
    return $retorno;
}

// Recebe uma matriz, transforma em json e criptografa, retornando o hash
function criptografa($dados)
{
    // matriz para json
    $dados = json_encode($dados);
    // pega a chave publica, fornecida por quem vai receber a informação
    $key = openssl_pkey_get_public("file://./chave_publica.pem");
    // criptografa utilizando a chave pública
    openssl_public_encrypt($dados,$hash,$key);
    // retorna o hash codificado em base64
    return base64_encode($hash);
}

function descriptografa($hash)
{
    // pega a chave privada, de quem vai receber a informação
    $key = openssl_pkey_get_private("file://./chave_privada.pem");
    // decodifica a hash de base64
    $hash = base64_decode($hash);
    // realiza a descriptografia utilizando a chave privada
    openssl_private_decrypt($hash,$dados,$key);
    // retorna os dados em matriz
    return json_decode($dados);
}
?>