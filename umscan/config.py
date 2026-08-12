"""Tunables and the noise lists that keep the crawl focused."""

from dataclasses import dataclass, field

SEED_URLS = ["https://www.umich.edu/"]

# www.umich.edu and many of its sibling hosts sit behind a Cloudflare
# JavaScript interstitial that a plain HTTP client cannot pass. When the
# primary seed returns nothing parseable we re-enter the umich.edu namespace
# through hosts that serve ordinary HTML, so a blocked front door does not
# reduce the whole inventory to one row.
FALLBACK_SEEDS = [
    "https://www.lib.umich.edu/",
    "https://arts.umich.edu/",
    "https://publichealth.umich.edu/",
    "https://taubmancollege.umich.edu/",
    "https://med.umich.edu/",
    "https://seas.umich.edu/",
    "https://cse.engin.umich.edu/",
    "https://isr.umich.edu/",
    "https://ns.umich.edu/",
    "https://myumi.ch/",
]

# Anything at or under these hosts counts as internal.
INTERNAL_SUFFIXES = ("umich.edu",)

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 UM-Inventory-Scanner/0.1"
)

# Registrable domains that are never worth inventorying: social, CDNs,
# analytics, shorteners, standards bodies, and the academic plumbing that
# shows up on every university page.
NOISE_DOMAINS = {
    # search / big tech utilities
    "google.com", "googleusercontent.com", "googleapis.com", "gstatic.com",
    "googletagmanager.com", "google-analytics.com", "doubleclick.net",
    "goo.gl", "youtube.com", "youtu.be", "ytimg.com", "blogger.com",
    "apple.com", "microsoft.com", "office.com", "live.com", "bing.com",
    "windows.net", "azureedge.net", "amazon.com", "amazonaws.com",
    "adobe.com", "oracle.com", "ibm.com", "salesforce.com",
    # social
    "facebook.com", "fb.com", "fb.me", "messenger.com", "instagram.com",
    "twitter.com", "x.com", "t.co", "linkedin.com", "licdn.com",
    "tiktok.com", "pinterest.com", "reddit.com", "redd.it", "tumblr.com",
    "snapchat.com", "threads.net", "flickr.com", "vimeo.com", "twitch.tv",
    "whatsapp.com", "telegram.org", "discord.com", "discord.gg",
    "mastodon.social", "bsky.app", "spotify.com", "soundcloud.com",
    "podcasts.apple.com", "buzzsprout.com",
    # dev / CDN / infrastructure
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "cloudflare.com", "cloudfront.net", "jsdelivr.net", "unpkg.com",
    "jquery.com", "bootstrapcdn.com", "fontawesome.com", "typekit.net",
    "cdnjs.com", "npmjs.com", "stackoverflow.com", "sentry.io",
    # standards / licenses / generic references
    "w3.org", "schema.org", "creativecommons.org", "iana.org", "ietf.org",
    "unicode.org", "whatwg.org", "mozilla.org", "wordpress.org",
    "wordpress.com", "wikipedia.org", "wikimedia.org", "wikidata.org",
    "archive.org", "gnu.org", "opensource.org",
    # productivity / vendor SaaS commonly linked from .edu pages
    "zoom.us", "zoom.com", "dropbox.com", "box.com", "slack.com",
    "eventbrite.com", "mailchimp.com", "constantcontact.com",
    "surveymonkey.com", "qualtrics.com", "docusign.com", "smartsheet.com",
    "atlassian.net", "canva.com", "adobeconnect.com", "handshake.com",
    "joinhandshake.com", "workday.com", "myworkday.com", "peoplesoft.com",
    "servicenow.com", "duosecurity.com", "okta.com", "ellucian.com",
    "blackboard.com", "instructure.com", "canvaslms.com", "turnitin.com",
    "proquest.com", "ebsco.com", "overdrive.com", "libguides.com",
    # form builders, site builders and campus vendor tooling
    "forms.gle", "google.com", "jotform.com", "typeform.com", "wufoo.com",
    "tfaforms.net", "formassembly.com", "surveygizmo.com", "alchemer.com",
    "squarespace.com", "squarespace-cdn.com", "wix.com", "weebly.com",
    "cargo.site", "activehosted.com", "activecampaign.com", "hubspot.com",
    "calendly.com", "libcal.com", "libapps.com", "springshare.com",
    "teamdynamix.com", "drupal.org", "handle.net", "issuu.com",
    "flipsnack.com", "smore.com", "bit.ly", "tinyurl.com", "ow.ly",
    # scholarly plumbing (never UM-affiliated, extremely common)
    "doi.org", "orcid.org", "crossref.org", "jstor.org", "sciencedirect.com",
    "springer.com", "springernature.com", "nature.com", "wiley.com",
    "elsevier.com", "tandfonline.com", "sagepub.com", "plos.org",
    "arxiv.org", "biorxiv.org", "ssrn.com", "researchgate.net",
    "semanticscholar.org", "mendeley.com", "zotero.org", "clarivate.com",
    "webofscience.com", "scopus.com", "ncbi.nlm.nih.gov", "pubmed.gov",
}

# Substring markers for hosts that are noise regardless of registrable domain.
NOISE_HOST_MARKERS = ("cdn.", "static.", "assets.", "fonts.", "analytics.")

# Non-HTML resources we never queue.
SKIP_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".zip", ".gz", ".tgz", ".bz2", ".7z", ".rar", ".tar",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tif",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".wav", ".m4a", ".webm",
    ".css", ".js", ".json", ".xml", ".rss", ".atom", ".ics", ".vcf",
    ".exe", ".dmg", ".pkg", ".deb", ".rpm", ".apk", ".iso", ".csv",
}

# Paths tried, in order, when hunting for a contact address on a domain.
CONTACT_PATHS = ["/contact", "/contact-us", "/contact/", "/about/contact", "/about-us/contact"]


@dataclass
class Settings:
    """Everything the operator can dial without editing code."""

    seeds: list = field(default_factory=lambda: list(SEED_URLS))
    fallback_seeds: list = field(default_factory=lambda: list(FALLBACK_SEEDS))
    pages_per_domain: int = 10
    max_pages: int = 2000         # 0 = crawl until the frontier is exhausted
    max_domains: int = 0          # 0 = unlimited
    crawl_workers: int = 8
    profile_workers: int = 6
    whois_workers: int = 3        # WHOIS servers rate-limit hard; keep low
    http_timeout: float = 20.0
    whois_timeout: float = 15.0
    per_host_delay: float = 0.4   # politeness gap between hits on one host
    max_bytes: int = 2_000_000
    contact_paths: int = 2        # how many CONTACT_PATHS to try per domain
    skip_whois: bool = False
    skip_contacts: bool = False
    output: str = "inventory.csv"
    evidence_output: str = ""     # optional audit sidecar
    verbose: bool = False
