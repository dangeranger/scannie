rule PDF_Risky_Actions
{
  meta:
    description = "Flags PDF active-content and risky document-action indicators"
    severity = "review"
    category = "packaged heuristic"
  strings:
    $pdf = "%PDF-" ascii
    $js1 = "/JS" ascii nocase
    $js2 = "/JavaScript" ascii nocase
    $open = "/OpenAction" ascii nocase
    $aa = "/AA" ascii nocase
    $launch = "/Launch" ascii nocase
    $embed = "/EmbeddedFile" ascii nocase
    $rich = "/RichMedia" ascii nocase
    $xfa = "/XFA" ascii nocase
    $submit = "/SubmitForm" ascii nocase
  condition:
    $pdf at 0 and (
      any of ($js*) or $open or $aa or $launch or $embed or $rich or $xfa or $submit
    )
}
