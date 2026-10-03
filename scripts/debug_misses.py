import sys; sys.path.insert(0, ".")
import tldextract as t
_T = t.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
from backend.app.services.url_analyzer import parse_url, analyse_url

urls = [
    "https://self-secureauthorise-personal.com/lloyds/login.php",
    "https://www.teknosayfasi.com/wp-admin/includes/cvv/log.htm",
    "https://claim4.apps-tipe.my.id",
    "https://followpersonalfinance.com/citroncommodities/doc-new/index.php",
    "https://co.ip.yqchl.com",
    "https://helpid-259620.2018337.com/?content_id=1ergdxwkuhrdnln",
]

for url in urls:
    e = _T(url)
    p = parse_url(url)
    hyphens = e.domain.count("-")
    _, score, level, ind, _ = analyse_url(url)
    ids = [i.id for i in ind]
    print(f"\n{url[:70]}")
    print(f"  domain={e.domain!r} suffix={e.suffix!r} hyphens={hyphens}")
    print(f"  path={p.path!r}")
    print(f"  score={score} level={level} ids={ids}")
