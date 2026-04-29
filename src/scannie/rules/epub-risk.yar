rule EPUB_Risky_Web_Content
{
  meta:
    description = "Flags EPUB script, network, embed, and remote-resource indicators"
    severity = "review"
    category = "packaged heuristic"
  strings:
    $script = "<script" ascii nocase
    $jsuri = "javascript:" ascii nocase
    $onload = "onload=" ascii nocase
    $onclick = "onclick=" ascii nocase
    $onerror = "onerror=" ascii nocase
    $fetch = "fetch(" ascii nocase
    $xhr = "XMLHttpRequest" ascii
    $ws = "WebSocket" ascii
    $iframe = "<iframe" ascii nocase
    $object = "<object" ascii nocase
    $embed = "<embed" ascii nocase
    $remote1 = "http://" ascii nocase
    $remote2 = "https://" ascii nocase
  condition:
    any of them
}
