#!/usr/bin/env python3
"""
gh-stars-lists: keep every GitHub star in exactly one GitHub List.

A scored regex classifier PROPOSES a list for each unlisted (or multi-listed) star. Nothing is
applied until a human-reviewed manifest is run with --confirm; every mutation is read back live
and journaled, and any manifest can be rolled back.

Usage:
  python gh_stars_lists.py                          # Read-only audit of the 30 most recent stars
  python gh_stars_lists.py --limit 100              # Read-only audit of the 100 most recent stars
  python gh_stars_lists.py --audit                  # Read-only audit of the whole account (exit 1 if not compliant)
  python gh_stars_lists.py --plan FILE.json         # Full scan -> review manifest (review: PENDING), no mutation
  python gh_stars_lists.py --apply-manifest FILE.json            # Dry-run: validate + live state check per op
  python gh_stars_lists.py --apply-manifest FILE.json --confirm  # Mutate serially, readback each op, JSONL journal
  python gh_stars_lists.py --apply-manifest FILE.json --rollback [--confirm]   # Undo a manifest (from <-> to)
  python gh_stars_lists.py --export-catalog [PATH]  # Render a Markdown catalog of your lists (stdout if no PATH)
  python gh_stars_lists.py --taxonomy               # Print the list names the classifier can propose
  python gh_stars_lists.py --test                   # Offline unit tests (classifier, catalog renderer, manifest)

Add --account LOGIN to any command to refuse running under a different `gh` login.
"""

import json, subprocess, sys, argparse, re, os, datetime, time

# Domain-first precedence tiers (rules explained in README.md, "How the classifier decides")
# Format: list of (Folder, regex_patterns). Each distinct pattern that matches adds 1 to the folder's
# score (+1 more when it matches inside the repo name). Patterns are matched against
# "owner/name description topics", lowercased; "-", "_" and "." in the repo name are read as spaces,
# so hyphenated patterns use "[- ]" to match both the name and hyphenated topics.
#
# Avoid generic words that also appear in unrelated repos: `auth` matched the topic
# "next-auth", `token` matched "token harvesting"/LLM tokens, `server` matched every "MCP server",
# `editing`/`markdown` pulled video and crawler repos into Writing. Use STRICT() for words that must
# not count when they are only part of a hyphenated topic such as "sound-design" or "vercel-ai-gateway".

def STRICT(word):
    """Pattern that matches `word` only as a standalone token, not inside a hyphenated compound."""
    return rf"(?<![\w-]){word}(?![\w-])"

# Tier 1: strong signals that decide the list on their own, before any domain scoring.
TIER_1_STRONG = [
    ("Router", [r"\b9router\b", r"2api\b", r"\bweb2api\b", r"(?<!vercel )(?<![\w-])ai[- ]gateway(?![\w-])", r"\bllm[- ](?:gateway|proxy|router|routing)\b",
                STRICT(r"ai[- ]proxy"), r"\bapi[- ]relay\b", r"\bopenai[- ]compatible (?:shim|wrapper)\b", r"中转", r"\bfake (?:ai|llm) apis?\b",
                r"\b(?:gemini|chatgpt|claude|openai|grok|deepseek|qwen|kimi|copilot|codex)[-_ ](?:bridge|relay|proxy)\b"]),
    # Tools whose output is a skill (book-to-skill, "turn X into a Claude Code skill") are cross-domain Skills.
    ("Skills", [r"\b[\w.]+-to-skills?\b", r"\binto (?:an? )?(?:[\w-]+ ){0,3}skills?\b", r"\bskills? (?:generator|creator|builder|factory)\b"]),
    # Personal search over the user's own machine (DigUp): the file types it indexes (photos, videos) are not its domain.
    ("Productivity", [r"\bdesktop[- ]search\b", r"\bsearch (?:your|the files on your) (?:computer|pc|mac|machine)\b",
                      r"\bfiles? on your (?:computer|pc|mac|machine)\b"]),
    # Audience research on a social platform is Socmed even when the platform is YouTube (21 Nov 2026,
    # precedent ScrapeCreators/social-media-research-skills).
    ("Socmed", [r"\b(?:youtube|tiktok|instagram|twitter|reddit|linkedin|social[- ]media)[- ](?:research|growth|creators?|audience)\b"]),
    # Skill packs addressed to designers belong to Design, whatever coding agent runs them (MengTo/Skills).
    ("Design", [r"\bfor (?:ui |ux |web |product )?designers\b"]),
]

TIER_2_BUSINESS_DOMAINS = [
    # Crypto evaluated before Stocks so "crypto trading" routes to Crypto
    ("Crypto", [r"\bcrypto\b", r"\bcryptocurrenc(?:y|ies)\b", r"\bweb3\b", r"\bsolana\b", r"\bethereum\b", r"\bdefi\b", r"\bonchain\b",
                r"\bdex\b", r"\bblockchain\b", r"\bbitcoin\b", r"\bbinance\b", r"\bmemecoins?\b", r"\bairdrops?\b", r"\bliquidity\b"]),
    ("Stocks", [r"\bstocks?\b", r"\bsaham\b", r"\bidx\b", r"\bihsg\b", r"\btrading\b", r"\btraders?\b", r"\bquant(?:s|itative)?\b",
                r"\bcharting\b", r"\btechnical[- ]analysis\b", r"\btradingview\b", r"\bpine ?script", r"\bscreeners?\b",
                r"\bmarket[- ]data\b", r"\bbacktest", r"\bequity\b", r"\bforex\b", r"\bopenbb\b"]),
    ("Finance", [r"\bqris\b", r"\bpayments?\b", r"\bpayment[- ]gateway\b", r"\bduit\b", r"\bbanking\b", r"\binvoices?\b", r"\bcheckout\b",
                 r"\bmoney ?lover\b", r"\bbudget(?:ing)?\b", r"\baccounting\b", r"\bfinance\b", r"\bdonations?\b", r"\bpembayaran\b",
                 r"\bmutasi\b", r"\bmerchants?\b", r"\bgopay\b"]),
    ("Documents", [r"\bpdf\b", r"\bdocuments?\b", r"\bdocx\b", r"\bexcel\b", r"\bspreadsheets?\b", r"\bsheet\b", r"\bocr\b",
                   r"\bpresentations?\b", r"\btakumi\b", r"\bforme\b", r"\bunstructured (?:text|data)\b"]),
    ("Mobile", [r"\bandroid\b", r"\bios\b", r"\biphone\b", r"\bflutter\b", r"\breact[- ]native\b", r"\bapk\b", r"\bmobile\b", r"\bswift\b",
                r"\bkotlin\b", r"\bphones?\b", r"\bemulators?\b", r"\bscrcpy\b"]),
    ("Design", [STRICT("design"), r"\bdesign[- ]systems?\b", r"\btailwind\b", STRICT("ui"), r"\bux\b", r"\bcomponents?\b",
                r"\bshadcn\b", r"\bcss\b", r"\bfigma\b", r"\bdiagrams?\b", r"\bexcalidraw\b", r"\banimations?\b", r"\bmotion\b",
                r"\bfront[- ]?end\b", r"\bwhiteboard\b", r"\billustrations?\b", r"\binterfaces?\b",
                # Web graphics runtimes (three.js, PixiJS, p5.js, physics): canvas/WebGL libraries for frontend motion (7 Nov 2026)
                r"\bwebgl\b", r"\bcanvas\b", r"\bshaders?\b", r"\bphysics engines?\b", r"\bvector graphics\b", r"\bgltf\b",
                r"\bp5(?:\.| )?js\b", r"\bcreative coding\b", r"\b(?:2d|3d) (?:library|graphics|scenes?|engine)\b",
                r"\b(?:motion|text|visual) effects?\b",
                # 3D tools, animation libraries, web design references (21 Nov 2026 review)
                r"\bblender\b", r"\bthree\.?js\b", r"\bgsap\b", r"\bgreensock\b", r"\b3d[- ](?:model(?:s|ing)?|visuals?)\b",
                r"\blanding[- ]pages?\b", r"\bweb[- ]design\b", r"\bdesign[- ]inspiration\b", r"\bawwwards\b", r"\bdesigners?\b",
                r"\bmicro[- ]?transitions?\b", r"\bicons?\b"]),
    ("Video & Images", [r"\bvideos?\b", r"\bvideo[- ]?editor\b", r"\bffmpeg\b", r"\bremotion\b", r"\bimages?\b", r"\bimage[- ]generation\b",
                        r"\brendering\b", r"\bphotos?\b", r"\bopencv\b", r"\bscreen[- ]?(?:recorder|recording|capture)\b", r"\bscreencast\b",
                        r"\bsubtitles?\b", r"\bcapcut\b", r"\bobs\b", r"\brtmp\b", r"\byoutube\b", r"\bdownloader\b", r"\bclips?\b",
                        r"\bshorts\b", r"\breels\b", r"\bcomfyui\b",
                        # Films made in code, motion graphics, video-generation models (7 Nov 2026)
                        r"\bfilms?\b", r"\bmotion[- ]graphics?\b", r"\bcartoons?\b", r"\brenders\b", r"\bgl[- ]transitions\b",
                        r"\bvideo[- ]generation\b", r"\bveo\b", r"\bsora\b", r"\bkling\b", r"\bseedance\b",
                        # Cameras and streams (precedent go2rtc), animated explainers (21 Nov 2026)
                        r"\brtsp\b", r"\bonvif\b", r"\bcctv\b", r"\bip[- ]cameras?\b", r"\bnvr\b",
                        r"\banimated (?:visuals?|explainers?|videos?)\b", r"\bstoryboard", r"\bcamera moves?\b", r"\bnarration\b"]),
    ("Audio", [r"\baudio\b", r"\btts\b", r"\bstt\b", r"\btext[- ]to[- ]speech\b", r"\bspeech\b", r"\belevenlabs\b", r"\bvoices?\b",
               r"\bvoice[- ]clon(?:e|ing)\b", r"\bwhisper\b", r"\bmusic\b", r"\bpodcasts?\b", r"\bdubbing\b", r"\bsound\b",
               r"\btranscription\b"]),
    ("Writing", [r"\bwriting\b", r"\bcopywriting\b", r"\bgrammar\b", r"\bprose\b", r"\bessays?\b", r"\bproofread"]),
    ("Socmed", [r"\btwitter\b", r"\bx\.com\b", r"\binstagram\b", r"\btiktok\b", r"\bdouyin\b", r"\btelegram\b", r"\bwhatsapp\b",
                r"\bsocial\b", r"\bsocial[- ]media\b", r"\bthreads\b", r"\bfacebook\b", r"\blinkedin\b", r"\breddit\b", r"\bbluesky\b", r"\bsocials\b",
                # Discord (not "join our discord.gg" links), Hacker News, the X API, follower growth (21 Nov 2026)
                r"\bdiscord\b(?!\.gg)", r"\bdiscord[- ]bots?\b", r"\bhacker ?news\b", r"\bhn\b", r"\bx api\b", r"\bfollowers\b"]),
    ("Marketing", [r"\bseo\b", r"\bmarketing\b", r"\banalytics\b", r"\bconversion\b", r"\bfunnel\b", r"\bads\b", r"\badvertising\b",
                   r"\bgrowth\b", r"\bcro\b", r"\bkeyword[- ]research\b", r"\bbacklinks?\b", r"\boutreach\b", r"\bb2b\b"]),
    ("Mail", [r"\bmail\b", r"\bemails?\b", r"\binbox\b", r"\bsmtp\b", r"\bresend\b", r"\bnewsletters?\b", r"\bgmail\b"]),
    ("Productivity", [r"\btodos?\b", r"\btask\b", r"\bnotes?\b", r"\bcalendar\b", r"\bscheduling\b", r"\blauncher\b", r"\bproductivity\b",
                      r"\bnotion\b", r"\btodoist\b", r"\btext[- ]expan(?:der|sion)\b", r"\bphrases\b",
                      r"\bdeals? aggregator\b", r"\bfreebies\b"]),
    ("Cloud & Storage", [r"\bs3\b", r"\bstorage\b", r"\bbackups?\b", r"\bsync\b", r"\brclone\b", r"\bminio\b", r"\bcloud[- ]storage\b",
                         r"\bremotely[- ]save\b", r"\blivesync\b", r"\bsyncthing\b", r"\bgoogle drive\b", r"\bonedrive\b", r"\bdropbox\b",
                         r"\bfile[- ]manager\b",
                         # Databases (precedent supabase), file sharing, chat archives (precedent telegram_backup), 21 Nov 2026
                         # "database"/"postgresql" are mostly stack topics (cal.diy, meilisearch): only bare "postgres" counts
                         r"\bpostgres\b", r"\bfile[- ](?:sharing|transfer)\b",
                         r"\balternative to airdrop\b", r"\barchiv(?:al|er|ing)\b", r"\bchat[- ]?(?:logs?|history|exporter)\b"]),
    ("Infra", [r"\bdocker\b", r"\bkubernetes\b", r"\bk8s\b", r"\bvps\b", r"\btailscale\b", r"\bwireguard\b", r"\bdeploy(?:ment)?\b",
               r"\bcontainers?\b", r"\bdevops\b", r"\bci[- ]cd\b", r"\bgithub actions\b", r"\bcloudflare\b", r"\bdns\b", r"\bsubdomains?\b",
               r"\bnetworking\b", r"\bvpn\b", r"\bwebsockets?\b", r"\bpush notifications?\b", r"\bfcm\b",
               # Remote desktop, deploy-to-phone (rustdesk, dukoi), 21 Nov 2026; "self-hosting" is too common to count
               r"\bremote[- ]desktop\b", r"\bvnc\b", r"\brdp\b", r"\bteamviewer\b", r"\banydesk\b",
               r"\bcloudflare[- ]tunnel\b", r"\bcloud bill\b"]),
    ("Security", [r"\bsecurity\b", r"\bcyber ?security\b", r"\bpentest(?:ing)?\b", r"\bpenetration[- ]test(?:ing)?\b", r"\bexploits?\b", r"\breverse[- ]engineering\b",
                  r"\bvuln(?:erabilit(?:y|ies))?\b", r"\bhack(?:ing|er|ers)?\b", r"\bfingerprint(?:ing)?\b", r"\bosint\b",
                  # Password managers / credential vaults; "how any software works" = reverse engineering (21 Nov 2026)
                  r"\bbitwarden\b", r"\bvaultwarden\b", r"\b1password\b", r"\bkeepass\w*\b", r"\bpassword[- ]managers?\b",
                  r"\bhow (?:any |the )?software works\b"]),
    ("Research", [r"\bresearch(?:es|er|ers)?\b", r"\bpapers?\b", r"\bacademic\b", r"\barxiv\b", r"\bliterature\b", r"\bscientific\b",
                  r"\bdeep[- ]?research\b", r"\bnotebooklm\b"]),
]

TIER_3_AI_SPECIALTIES = [
    ("Router", [r"\b9router\b", r"\bproxy\b", r"\bgateway\b", r"\bone[- ]api\b", r"\bnew[- ]api\b", r"\blitellm\b", r"\breverse[- ]proxy\b",
                r"\bweb2api\b", r"\bopenai[- ]compatible\b", r"\bcompatible api\b", r"\bfree[- ]ai\b", r"\bfree[- ]tier\b", r"\bresellers?\b", r"\bquotas?\b",
                r"\bproviders?\b", r"\bcredits\b", r"\bmulti(?:ple)?[- ](?:[\w-]+ ){0,3}accounts?\b", r"\brate[- ]limit rotation\b",
                # Free LLM API lists, account switchers, sign-up/invite-code farming (21 Nov 2026)
                r"\bfree[- ]?llm\b", r"\bfree[- ]models?\b", r"\baccount[- ]switch(?:er|ing|board)?\b", r"\bswitch between (?:[\w-]+ ){0,2}accounts\b",
                r"邀请码", r"注册", r"\binvite[- ]codes?\b"]),
    ("AI Models", [r"\bvllm\b", r"\bgguf\b", r"\bollama\b", r"\bunsloth\b", r"\btransformers?\b", r"\bdiffusion\b", r"\bweights\b",
                   r"\bllms?\b", r"\bai models?\b", r"\bfoundation models?\b", r"\blanguage models?\b", r"\bfine-?tun", r"\binference\b",
                   r"\bllama\.?cpp\b", r"\bmlx\b", r"\bon-device\b",
                   # Computer-vision / ML model families (ultralytics), 21 Nov 2026
                   r"\bcomputer[- ]vision\b", r"\bobject[- ]detection\b", r"\bdeep[- ]learning\b", r"\bmachine[- ]learning\b",
                   r"\byolo\w*\b"]),
    ("AI Decisions", [r"\btyped decisions\b", r"\bsemantic[- ]ifs?\b", r"\bjev\b", r"\bjevcache\b", r"\bclassifier\b", r"\btype-?safe\b",
                      r"\bdecision[- ](?:cache|making)\b"]),
    ("Memory", [r"\bpersistent memory\b", r"\bmemory\b", r"\bmemories\b", r"\brecall\b", r"\brag\b", r"\bhindsight\b", r"\bmem0\b",
                r"\bsecond[- ]brain\b", r"\blong[- ]term[- ]memory\b", r"\bvector[- ](?:database|search)\b", r"\bembeddings?\b"]),
    ("Code", [r"\bcoding\b", r"\bcopilot\b", r"\bide\b", r"\beditor\b", r"\blinter\b", r"\bcompiler\b", r"\bdevin\b", r"\bcursor\b",
              r"\bcode[- ]intelligence\b", r"\bcodebases?\b", r"\bshell\b", r"\bclaude\.md\b", r"\bcode[- ](?:graph|search|analysis|review)\b", r"\bcoding[- ]agents?\b",
              # Codebase audits, learn-to-code project lists (21 Nov 2026)
              r"\baudit (?:your |the )?codebases?\b", r"\bproject ideas\b"]),
    ("Computer Use", [r"\bcomputer[- ]use\b", r"\bdesktop[- ]automation\b", r"\bgui[- ]agent\b", r"\bpyautogui\b"]),
    ("Browser", [r"\bbrowser engine\b", r"\bbrowsers?\b", r"\bbrowser[- ]automation\b", r"\bplaywright\b", r"\bpuppeteer\b", r"\bcdp\b",
                 r"\bchromium\b", r"\bheadless\b", r"\bcaptcha\b", r"\bcamoufox\b", r"\banti-?bot\b", r"\bstealth\b", r"\bweb agents?\b",
                 r"\bdevtools\b"]),
    ("Crawl", [r"\bcrawlers?\b", r"\bcrawl\b", r"\bscrapers?\b", r"\bscraping\b", r"\bfirecrawl\b", r"\bspider\b",
               r"\b(?:data|content) extraction\b"]),
    # Bare "agent(s)" is not a signal: nearly every AI repo says it. Only agent-platform wording counts.
    ("Agent", [r"\bai[- ]agents?\b", r"\bmulti[- ]agent\b", r"\borchestrat", r"\bcrewai\b", r"\bautogen\b", r"\blangchain\b",
               r"\blanggraph\b", r"\bautonomous\b", r"\bagentic\b", r"\bcoworkers?\b",
               r"\bagents? (?:harness|executor|framework|platform|runtime|workspace|team)s?\b",
               r"\bteam of (?:ai )?(?:bots|agents)\b", r"\bai bots?\b"]),
]

TIER_4_GENERIC_FORMATS = [
    # Formats beat a Tier 2 domain winner only by a 2+ point lead (moneylover-mcp stays in Finance,
    # pdf-mcp in Documents). References is a fallback: used only when no other Tier 3/4 folder matched.
    ("Skills", [r"\bskills?\b", r"skill\.md"]),
    ("Prompts", [r"\bprompts?\b", r"\bsystem[- ]prompts?\b", r"\bjailbreaks?\b", r"\bprompt-engineering\b"]),
    ("API & MCP", [r"\bmcp\b", r"\bmodelcontextprotocol\b", r"\bmodel context protocol\b", r"\bapis?\b", r"\bendpoints?\b", r"\bsdks?\b",
                   r"\bconnectors?\b", r"\bregistry\b", r"\bfunction[- ]calling\b", r"\bfor agent tools\b"]),
    ("References", [r"\bawesome\b", r"\bcheat-?sheets?\b", r"\bhandbook\b", r"\bcurated\b", r"\bresources\b", r"\bmanuals?\b",
                    r"\bchecklist\b"]),
]

# Tie-break order for Tier 3/4 when scores are equal: specific AI specialties first, then generic
# formats, then the catch-all specialties (AI Models, Agent) that almost every AI repo mentions.
TIER_34_TIE_ORDER = ["Router", "AI Decisions", "Code", "Computer Use", "Browser", "Crawl", "Memory",
                     "Skills", "Prompts", "API & MCP", "AI Models", "Agent"]
TIER_FALLBACK = "References"

def _repo_texts(repo):
    nwo = repo.get('nameWithOwner', '') or ''
    owner, _, name = nwo.partition('/')
    name = re.sub(r"[-_.]", " ", name.lower())
    desc = (repo.get('description') or '').lower()
    topics = [t['topic']['name'].lower() for t in (repo.get('repositoryTopics') or {}).get('nodes', [])]
    combined = f"{owner.lower()}/{name} {desc} {' '.join(topics)}"
    return owner.lower(), name, combined

def _score(table, name, combined):
    """Returns {folder: (score, [matched patterns])} for folders with at least one hit."""
    scores = {}
    for folder, patterns in table:
        hits = [p for p in patterns if re.search(p, combined)]
        if hits:
            scores[folder] = (len(hits) + sum(1 for p in hits if re.search(p, name)), hits)
    return scores

def _fmt(scores):
    return ", ".join(f"{f} {s}" for f, (s, _) in sorted(scores.items(), key=lambda kv: -kv[1][0]))

def classify_detail(repo):
    """
    Classifies a repository and returns (folder, reason).

    Precedence (domain-first, scored):
      Tier 1   strong signals (Router, Skills, Productivity, Socmed, Design patterns) decide alone.
      Tier 2   business domains. The top domain wins when it scores at least 2x the runner-up or
               leads by 2+; otherwise Crypto beats Stocks and Documents beats the rest; any other
               tie is ambiguous (except two-way Crypto > Stocks, Stocks > Finance, and Documents > the rest).
      Tier 3   AI specialties can take a repo from a Tier 2 winner only by scoring strictly higher.
      Tier 4   generic formats beat a Tier 2 winner only by leading 2+ points (a prompt-leak
               collection that mentions "Claude Design"); otherwise they compete with Tier 3 on
               score (ties by TIER_34_TIE_ORDER) when Tier 2 has no winner.
      Fallback References only when no other Tier 3/4 folder matched; Others when Tier 2 stays
               ambiguous and nothing outscores it, or when no pattern matched.
    """
    owner, name, combined = _repo_texts(repo)

    # Tier 1: strong signals
    strong = _score(TIER_1_STRONG, name, combined)
    if strong:
        order = [f for f, _ in TIER_1_STRONG]
        folder = max(strong, key=lambda f: (strong[f][0], -order.index(f)))
        return folder, f"Tier 1: strong {folder} signal ({', '.join(strong[folder][1])})"

    # Tier 2: specific business & functional domains
    t2 = _score(TIER_2_BUSINESS_DOMAINS, name, combined)
    t2_order = [f for f, _ in TIER_2_BUSINESS_DOMAINS]
    t2_ranked = sorted(t2, key=lambda f: (-t2[f][0], t2_order.index(f)))
    t2_winner, t2_top = None, 0
    if t2_ranked:
        t2_top = t2[t2_ranked[0]][0]
        runner_up = t2[t2_ranked[1]][0] if len(t2_ranked) > 1 else 0
        close = [f for f in t2_ranked if 2 * t2[f][0] > t2_top]
        if t2_top >= 2 * runner_up or t2_top - runner_up >= 2:
            t2_winner = t2_ranked[0]
        elif set(close) == {"Crypto", "Stocks"}:
            t2_winner = "Crypto"  # Crypto takes precedence over Stocks
        elif set(close) == {"Stocks", "Finance"}:
            t2_winner = "Stocks"  # "finance" is generic wording in trading repos
        elif "Documents" in close:
            t2_winner = "Documents"
        elif "Video & Images" in close and set(close) <= {"Design", "Video & Images", "Audio"}:
            t2_winner = "Video & Images"  # animation + sound that ends as a film is video production (7 Nov 2026)

    # Tier 3 (AI specialties) and Tier 4 (generic formats, References kept aside as fallback)
    tier3_names = {f for f, _ in TIER_3_AI_SPECIALTIES}
    t34 = _score(TIER_3_AI_SPECIALTIES + [t for t in TIER_4_GENERIC_FORMATS if t[0] != TIER_FALLBACK], name, combined)
    fallback = _score([t for t in TIER_4_GENERIC_FORMATS if t[0] == TIER_FALLBACK], name, combined)
    rank = lambda f: (-t34[f][0], TIER_34_TIE_ORDER.index(f))
    t3_winner = min((f for f in t34 if f in tier3_names), key=rank, default=None)
    t4_winner = min((f for f in t34 if f not in tier3_names), key=rank, default=None)
    t34_winner = min(t34, key=rank, default=None)
    ref_score = fallback[TIER_FALLBACK][0] if fallback and not t34 else 0
    detail = (f" | Tier 3/4: {_fmt(t34)}" if t34 else "")

    if t2_winner:
        s2 = t2[t2_winner][0]
        if t3_winner and t34[t3_winner][0] > s2:
            return t3_winner, f"Tier 3 beats Tier 2: {_fmt(t34)} | Tier 2: {_fmt(t2)}"
        if t4_winner and t34[t4_winner][0] >= s2 + 2:
            return t4_winner, f"Tier 4 format dominates: {_fmt(t34)} | Tier 2: {_fmt(t2)}"
        if ref_score >= s2 + 2:
            return TIER_FALLBACK, f"References dominates: {_fmt(fallback)} | Tier 2: {_fmt(t2)}"
        return t2_winner, f"Tier 2: {_fmt(t2)}" + detail
    if t34_winner and t34[t34_winner][0] > t2_top:
        return t34_winner, f"Tier 3/4: {_fmt(t34)}" + (f" | Tier 2: {_fmt(t2)}" if t2 else "")
    if ref_score > t2_top:
        return TIER_FALLBACK, f"Fallback: {_fmt(fallback)}" + (f" | Tier 2: {_fmt(t2)}" if t2 else "")
    if t2 or t34:
        return "Others", f"Ambiguous: Tier 2 {_fmt(t2)}" + detail
    return "Others", "No pattern matched"

def taxonomy():
    """Every list name the classifier can return, sorted case-insensitively."""
    names = {f for table in (TIER_1_STRONG, TIER_2_BUSINESS_DOMAINS, TIER_3_AI_SPECIALTIES, TIER_4_GENERIC_FORMATS)
             for f, _ in table}
    return sorted(names | {"Others"}, key=str.lower)

def classify_repo(repo):
    """Returns only the folder name from classify_detail()."""
    return classify_detail(repo)[0]

READ_RETRY_DELAYS = (3, 10, 30, 60)  # seconds; transient 5xx/timeouts (19 Oct), 502 outlasted 3+10s (19 Nov)
# "unexpected end of JSON input": gh got a truncated response body (seen twice in the 19 Nov dry-run).
TRANSIENT_GH_ERROR = re.compile(r"HTTP 5\d\d|timeout|EOF|unexpected end of JSON input", re.IGNORECASE)

def is_transient_gh_error(stderr):
    return bool(TRANSIENT_GH_ERROR.search(stderr or ''))

def gh_graphql(query, variables=None):
    """Runs one GraphQL call via gh. Read queries retry on transient 5xx/timeouts; mutations never retry,
    because a timed-out mutation may still have landed (the caller reads live state instead)."""
    is_mutation = query.lstrip().startswith('mutation')
    delays = () if is_mutation else READ_RETRY_DELAYS
    for attempt in range(len(delays) + 1):
        try:
            p = subprocess.run(
                ['gh', 'api', 'graphql', '--input', '-'],
                input=json.dumps({'query': query, 'variables': variables or {}}),
                capture_output=True, text=True, encoding='utf-8', timeout=60
            )
            transient = p.returncode and is_transient_gh_error(p.stderr)
        except subprocess.TimeoutExpired:
            if is_mutation:
                raise RuntimeError("gh timeout during mutation (state unknown, read it before retrying)")
            p, transient = None, True
        if not transient or attempt == len(delays):
            break
        time.sleep(delays[attempt])
    if p is None:
        raise RuntimeError("gh timeout after retries")
    if p.returncode:
        raise RuntimeError(f"gh error: {p.stderr.strip()}")
    r = json.loads(p.stdout)
    if r.get('errors'):
        raise RuntimeError(f"GraphQL error: {r['errors']}")
    return r['data']

LIST_ITEM_FIELDS = "id nameWithOwner url description isArchived"

def get_live_lists_paginated():
    """Fetches all user lists with complete paginated members.

    Returns (viewer_login, {list_name: {'id', 'description', 'members': {repo_id: nameWithOwner},
    'items': [{id, nameWithOwner, url, description, isArchived}]}}).
    """
    query_lists = """
    query($after: String) {
      viewer {
        login
        lists(first: 100, after: $after) {
          totalCount
          pageInfo { hasNextPage endCursor }
          nodes {
            id
            name
            description
            items(first: 100) {
              totalCount
              pageInfo { hasNextPage endCursor }
              nodes { ... on Repository { %s } }
            }
          }
        }
      }
    }
    """ % LIST_ITEM_FIELDS
    query_items = """
    query($id: ID!, $after: String) {
      node(id: $id) {
        ... on UserList {
          items(first: 100, after: $after) {
            pageInfo { hasNextPage endCursor }
            nodes { ... on Repository { %s } }
          }
        }
      }
    }
    """ % LIST_ITEM_FIELDS
    lists = {}
    after = None
    viewer_login = None
    while True:
        data = gh_graphql(query_lists, {'after': after})
        viewer_login = data['viewer']['login']
        for l in data['viewer']['lists']['nodes']:
            items_info = l['items']
            items = [r for r in items_info['nodes'] if r and r.get('id')]

            # Paginate list items if totalCount > 100
            item_page = items_info['pageInfo']
            while item_page['hasNextPage']:
                node_items = gh_graphql(query_items, {'id': l['id'], 'after': item_page['endCursor']})['node']['items']
                items.extend(r for r in node_items['nodes'] if r and r.get('id'))
                item_page = node_items['pageInfo']

            lists[l['name']] = {
                'id': l['id'],
                'description': l.get('description') or '',
                'members': {r['id']: r['nameWithOwner'] for r in items},
                'items': items,
            }

        if not data['viewer']['lists']['pageInfo']['hasNextPage']:
            break
        after = data['viewer']['lists']['pageInfo']['endCursor']

    return viewer_login, lists

def get_stars_paginated(limit=None, audit=False):
    """Fetches starred repositories with full pagination support."""
    query = """
    query($first: Int!, $after: String) {
      viewer {
        login
        starredRepositories(first: $first, after: $after, orderBy: {field: STARRED_AT, direction: DESC}) {
          totalCount
          pageInfo { hasNextPage endCursor }
          edges {
            starredAt
            node {
              id
              nameWithOwner
              description
              repositoryTopics(first: 20) {
                nodes { topic { name } }
              }
            }
          }
        }
      }
    }
    """
    stars = []
    after = None
    total_count = 0
    viewer_login = None

    while True:
        fetch_size = 100
        if not audit and limit is not None:
            remaining = limit - len(stars)
            if remaining <= 0:
                break
            fetch_size = min(100, remaining)

        data = gh_graphql(query, {'first': fetch_size, 'after': after})
        viewer_login = data['viewer']['login']
        c = data['viewer']['starredRepositories']
        total_count = c['totalCount']
        stars.extend(c['edges'])

        if not c['pageInfo']['hasNextPage']:
            break
        after = c['pageInfo']['endCursor']

        if not audit and limit is not None and len(stars) >= limit:
            break

    return viewer_login, total_count, stars

TARGET_ACCOUNT = None  # set from --account; None = whoever `gh` is logged in as
MONTHS = ["", "January", "February", "March", "April", "May", "June", "July", "August",
          "September", "October", "November", "December"]
EMPTY_SECTION = "*(empty)*"
MUTATION_UPDATE_LISTS = """
mutation($input: UpdateUserListsForItemInput!) {
  updateUserListsForItem(input: $input) {
    lists { id name }
  }
}
"""

def get_star_total():
    data = gh_graphql("query { viewer { login starredRepositories { totalCount } } }")
    return data['viewer']['login'], data['viewer']['starredRepositories']['totalCount']

def require_account(viewer_login):
    if TARGET_ACCOUNT and viewer_login.lower() != TARGET_ACCOUNT.lower():
        print(f"[X] FATAL: Authenticated user '{viewer_login}' does not match required target '{TARGET_ACCOUNT}'!")
        sys.exit(1)

# ---------------------------------------------------------------- catalog export

def render_catalog(account, lists, stars_total, generated):
    """Renders a Markdown catalog of all lists from list state.

    lists: {name: {'description', 'items': [{id, nameWithOwner, url, description, isArchived}]}}
    generated: datetime.date printed on the Generated line.
    Sections are sorted by list name and entries by repo name, both case-insensitive.
    """
    total_repos = len({it['id'] for l in lists.values() for it in l['items']})
    out = [
        "# GitHub Stars Catalog",
        "",
        f"> **Account:** {account} | **Total Repos:** {total_repos} ({stars_total} Starred) | **Lists:** {len(lists)}",
        f"> **Generated:** {generated.day} {MONTHS[generated.month]} {generated.year} | "
        f"**Source:** gh_stars_lists.py --export-catalog (live GraphQL snapshot)",
        "",
        f"Starred repositories of {account}, grouped into {len(lists)} GitHub Lists. "
        "Repos marked *(archived)* are no longer maintained by their owners.",
        "",
        "---",
    ]
    for name in sorted(lists, key=str.lower):
        lst = lists[name]
        items = sorted(lst['items'], key=lambda it: it['nameWithOwner'].lower())
        out += ["", f"## {name} ({len(items)})"]
        list_desc = " ".join((lst.get('description') or '').split())
        if list_desc:
            out.append(f"*{list_desc}*")
        out.append("")
        if not items:
            out.append(EMPTY_SECTION)
        for it in items:
            line = f"- [{it['nameWithOwner']}]({it['url']})"
            desc = " ".join((it.get('description') or '').split())
            if desc:
                line += f" — {desc}"
            if it.get('isArchived'):
                line += " *(archived)*"
            out.append(line)
    return "\n".join(out) + "\n"

def export_catalog(path):
    """Regenerates the catalog from live state. path '-' prints to stdout; any other path is written."""
    viewer_login, lists = get_live_lists_paginated()
    require_account(viewer_login)
    _, stars_total = get_star_total()
    text = render_catalog(viewer_login, lists, stars_total, datetime.date.today())
    entries = sum(len(l['items']) for l in lists.values())
    summary = f"[+] Catalog: {len(lists)} lists, {entries} entries, {stars_total} stars"
    if path == '-':
        sys.stdout.write(text)
        print(summary + " (stdout)", file=sys.stderr)
    else:
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
        print(f"{summary} -> {path}")

# ---------------------------------------------------------------- plan (classifier proposes, a reviewer decides)

def build_plan(viewer_login, lists, stars_total, stars_edges):
    """Builds a review manifest for every examined star that is unlisted or in more than one list."""
    repo_to_lists = {}
    for lname, ldata in lists.items():
        for rid in ldata['members']:
            repo_to_lists.setdefault(rid, set()).add(lname)

    ops, unlisted, multi = [], 0, 0
    for edge in stars_edges:
        node = edge['node']
        assigned = sorted(repo_to_lists.get(node['id'], set()))
        if len(assigned) == 1:
            continue
        target, reason = classify_detail(node)
        if target not in lists:
            reason += f" | list '{target}' does not exist on this account"
            target = "Others" if "Others" in lists else None
        if assigned:
            multi += 1
            group, frm, frm_id = "MULTI_LIST", assigned, [lists[n]['id'] for n in assigned]
        else:
            unlisted += 1
            group, frm, frm_id = "UNLISTED", None, None
        ops.append({
            "group": group,
            "repo": node['nameWithOwner'],
            "repo_id": node['id'],
            "starredAt": edge.get('starredAt'),
            "description": node.get('description'),
            "from": frm,
            "from_list_id": frm_id,
            "to": target,
            "to_list_id": lists[target]['id'] if target else None,
            "reason": f"classifier (needs review): {reason}",
        })

    return {
        "review": "PENDING",
        "instructions": [
            "The classifier only proposes. Review every op; open the repo README when the description is not enough.",
            "To change a target: set 'to' to the right list name and delete 'to_list_id' (it is resolved from the name at apply time).",
            "Delete ops you do not approve. An op whose 'to' is null must be filled in or deleted.",
            "When the review is done, set 'review' to 'APPROVED', run --apply-manifest <file> (dry-run), "
            "then --apply-manifest <file> --confirm.",
        ],
        "baseline": {
            "snapshot_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
            "account": viewer_login,
            "stars": stars_total,
            "examined": len(stars_edges),
            "lists": len(lists),
            "listed": len(stars_edges) - unlisted,
            "unlisted": unlisted,
            "multi_list": multi,
            "mutation": "updateUserListsForItem(input:{itemId:repo_id, listIds:[to_list_id]})",
            "rollback": "python gh_stars_lists.py --apply-manifest <file> --rollback --confirm (from <-> to, reverse order)",
        },
        "lists": {name: ldata['id'] for name, ldata in sorted(lists.items(), key=lambda kv: kv[0].lower())},
        "ops": ops,
    }

# ---------------------------------------------------------------- apply manifest (serial, state-checked, journaled)

def _names(value):
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]

def resolve_manifest(manifest, lists, rollback=False):
    """Validates a manifest against live lists before any mutation.

    Returns ops as dicts with 'expected_before' and 'target' (sorted list-id lists), in execution
    order (reversed for rollback). Raises ValueError listing every problem found.
    """
    problems = []
    review = manifest.get('review')
    if review == 'PENDING':
        problems.append("review is still PENDING: review every op first, then set \"review\": \"APPROVED\"")
    elif review != 'APPROVED':
        # Fail closed: only an explicit approval runs (also for --rollback)
        problems.append(f"review {review!r}: a manifest must contain \"review\": \"APPROVED\" after it is reviewed")
    ops = manifest.get('ops')
    if not isinstance(ops, list) or not ops:
        problems.append("ops is empty or not a list")
        ops = []

    def resolve(op, label, names_key, ids_key):
        names = _names(op.get(names_key))
        missing = [n for n in names if n not in lists]
        if missing:
            problems.append(f"{label}: list {missing} in '{names_key}' does not exist on the live account")
            return None
        live_ids = sorted(lists[n]['id'] for n in names)
        if op.get(ids_key) is not None and sorted(_names(op.get(ids_key))) != live_ids:
            problems.append(f"{label}: '{ids_key}' does not match '{names_key}' {names} "
                            f"(live: {live_ids}); delete '{ids_key}' when you change '{names_key}' during review")
            return None
        return live_ids

    seen, out = set(), []
    for i, op in enumerate(ops, 1):
        label = f"op #{i} ({op.get('repo') or op.get('repo_id')})"
        rid = op.get('repo_id')
        if not rid:
            problems.append(f"{label}: repo_id is empty")
            continue
        if rid in seen:
            problems.append(f"{label}: duplicate repo_id")
            continue
        seen.add(rid)
        frm_ids = resolve(op, label, 'from', 'from_list_id')
        to_ids = resolve(op, label, 'to', 'to_list_id')
        if frm_ids is None or to_ids is None:
            continue
        if len(to_ids) != 1:
            problems.append(f"{label}: 'to' must be exactly 1 list (got {op.get('to')!r})")
            continue
        if rollback:
            out.append({'repo': op.get('repo') or rid, 'repo_id': rid, 'from': op.get('to'), 'to': op.get('from'),
                        'expected_before': to_ids, 'target': frm_ids})
        else:
            out.append({'repo': op.get('repo') or rid, 'repo_id': rid, 'from': op.get('from'), 'to': op.get('to'),
                        'expected_before': frm_ids, 'target': to_ids})
    if problems:
        raise ValueError("\n".join(f"    - {p}" for p in problems))
    return out[::-1] if rollback else out

def read_repo_state(repo_id):
    """Live state of one repo: (sorted ids of lists containing it, viewerHasStarred; None if the repo is gone)."""
    _, lists = get_live_lists_paginated()
    list_ids = sorted(l['id'] for l in lists.values() if repo_id in l['members'])
    try:
        node = gh_graphql("query($id: ID!) { node(id: $id) { ... on Repository { viewerHasStarred } } }",
                          {'id': repo_id})['node']
    except RuntimeError as e:
        if "Could not resolve to a node" not in str(e):
            raise
        node = None
    return list_ids, (node.get('viewerHasStarred') if node else None)

def default_journal_path(manifest_path):
    root, _ = os.path.splitext(manifest_path)
    if root.endswith('-manifest'):
        return root[:-len('-manifest')] + '-journal.jsonl'
    return root + '-journal.jsonl'

def apply_manifest(path, confirm=False, rollback=False, journal_path=None):
    """Runs a reviewed manifest one op at a time. Without confirm it only checks live state (dry-run)."""
    with open(path, encoding='utf-8') as f:
        manifest = json.load(f)
    viewer_login, lists = get_live_lists_paginated()
    require_account(viewer_login)
    manifest_account = (manifest.get('baseline') or {}).get('account')
    if manifest_account and manifest_account != viewer_login:
        print(f"[X] Manifest is for account '{manifest_account}', not '{viewer_login}'.")
        return 2
    try:
        ops = resolve_manifest(manifest, lists, rollback)
    except ValueError as e:
        print(f"[X] Manifest rejected, no mutation was run:\n{e}")
        return 2

    names_by_id = {l['id']: n for n, l in lists.items()}
    show = lambda ids: "[" + ", ".join(names_by_id.get(i, i) for i in ids) + "]"
    journal_path = journal_path or default_journal_path(path)
    mode = ("ROLLBACK " if rollback else "") + ("APPLY" if confirm else "DRY-RUN")
    print(f"[*] {mode}: {len(ops)} ops from {path}")
    if confirm:
        print(f"[*] Journal: {journal_path}")

    counts = {}
    for op in ops:
        rid = op['repo_id']
        try:
            before, starred = read_repo_state(rid)
        except Exception as e:
            print(f"    {'ERROR_READ':20} {op['repo']}: {e}")
            print("[X] Stopped before mutating this op: live state could not be read. Run it again later "
                  "(ops already applied will read as ALREADY).")
            counts["ERROR_READ"] = counts.get("ERROR_READ", 0) + 1
            break
        entry = {"ts": datetime.datetime.now().isoformat(timespec='seconds'), "repo": op['repo'], "repo_id": rid,
                 "from": op['from'], "to": op['to'], "before_list_ids": before, "after_list_ids": before,
                 "still_starred": starred}
        if rollback:
            entry["mode"] = "rollback"
        if starred is None:
            result = "SKIP_NOT_FOUND"
        elif not starred:
            result = "SKIP_NOT_STARRED"
        elif before == op['target']:
            result = "ALREADY"
        elif before != op['expected_before']:
            result = "SKIP_STATE_MISMATCH"
        elif not confirm:
            result = "WOULD_APPLY"
        else:
            # No blind retry: whatever the mutation call returns, the live readback decides.
            try:
                gh_graphql(MUTATION_UPDATE_LISTS, {'input': {'itemId': rid, 'listIds': op['target']}})
            except Exception as e:
                entry["error"] = str(e)
            try:
                after, starred_after = read_repo_state(rid)
                entry.update(after_list_ids=after, still_starred=starred_after)
                if after == op['target'] and starred_after:
                    result = "OK_AFTER_ERROR" if "error" in entry else "OK"
                else:
                    result = "FAIL"
            except Exception as e:
                entry["readback_error"] = str(e)
                result = "UNVERIFIED"
        entry["result"] = result
        counts[result] = counts.get(result, 0) + 1
        print(f"    {result:20} {op['repo']}: {show(entry['before_list_ids'])} -> {show(op['target'])}"
              + (f" (now {show(entry['after_list_ids'])})" if confirm and result in ("FAIL", "OK", "OK_AFTER_ERROR") else ""))
        if confirm:
            with open(journal_path, 'a', encoding='utf-8') as jf:
                jf.write(json.dumps(entry, ensure_ascii=False) + "\n")
        if result in ("FAIL", "UNVERIFIED"):
            print("[X] Stopped: live state does not match the target. Check with --audit before continuing.")
            break

    print("-" * 65)
    print("[+] Summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if not confirm and counts.get("WOULD_APPLY"):
        print("[i] Dry-run only. Run again with --confirm to apply the mutations.")
    if confirm:
        print("[i] Final check: python gh_stars_lists.py --audit")
    clean = set(counts) <= {"OK", "OK_AFTER_ERROR", "ALREADY", "WOULD_APPLY"}
    return 0 if clean else 1

def _fixture(nwo, description, topics=()):
    """Builds a repo dict in the same shape the GraphQL star query returns."""
    return {
        "nameWithOwner": nwo,
        "description": description,
        "repositoryTopics": {"nodes": [{"topic": {"name": t}} for t in topics]},
    }

# Real misclassifications found by the 19 Oct 2026 re-audit.
# Descriptions and topics are copied verbatim from the starred repos at the time;
# expected targets are the human-reviewed placements.
REGRESSION_2026_10_19 = [
    # was Security: topic "next-auth" tripped \bauth\b
    (_fixture("calcom/cal.diy", "Scheduling infrastructure for absolutely everyone.",
              ["open-source", "typescript", "nextjs", "next-auth", "postgresql", "prisma", "t3-stack",
               "tailwindcss", "trpc", "turborepo", "zod"]), "Productivity"),
    # was Others: analytics + mobile + security topics collided across Tier 2
    (_fixture("matomo-org/matomo",
              "Empowering People Ethically 🚀 — Matomo is hiring! Join us → https://matomo.org/jobs Matomo is the "
              "leading open-source alternative to Google Analytics, giving you complete control and built-in privacy. "
              "Easily collect, visualise, and analyse data from websites & apps. Star us on GitHub ⭐️  – Pull Requests welcome! ",
              ["analytics", "php", "piwik", "log", "website", "privacy", "mobile", "intranet", "web-analytics",
               "marketing", "growth", "matomo", "mysql", "hacktoberfest", "security"]), "Marketing"),
    # was Others: "sound-design" pulled in Design next to Audio
    (_fixture("Leonxlnx/earshot",
              "Ears for coding agents: let AI hear, review and make sound. CPU-only, open source.",
              ["ai-agents", "audio", "claude-code", "mcp", "sound-design"]), "Audio"),
    # was Others: nothing matched; the repo name is the only signal
    (_fixture("CoderBhoid/gemini-bridge", "Just a sophisticated way to turn dumb chatbox llms into agents."), "Router"),
    # was Others: reverse-engineering (Security) + image & video + self-hosted collided across Tier 2
    (_fixture("zexadev/gemini-web2api-go",
              "Gemini web → OpenAI-compatible API, self-hosted, no API key. Reverse-proxies gemini.google.com into "
              "/v1/chat/completions: single Go binary, Chrome TLS fingerprint, cookie pool with auto-renewal, proxy pool, "
              "admin dashboard, SQLite/MySQL/PG, image & video generation · 把 Gemini 网页反代成 OpenAI 兼容 API",
              ["api-proxy", "chrome-fingerprint", "gemini", "gemini-api", "gemini-pro", "golang", "openai-api",
               "openai-compatible", "reverse-engineering", "gemini-proxy", "gemini-web-api", "gemini-web2api",
               "llm-gateway", "llm-proxy", "no-api-key", "openai-compatible-api", "self-hosted", "free-gemini-api"]), "Router"),
    # manual correction AI Models -> AI Decisions (topic "jev")
    (_fixture("TypeLLM/TypeLLM", "TypeLLM: LLMs with type-safe generation", ["ai", "types", "llms", "jev"]), "AI Decisions"),
    # manual correction Research -> API & MCP ("OpenRouter for agent tools", registry)
    (_fixture("superdesigndev/treg", "OpenRouter for agent tools. Join community here: https://discord.gg/6mQYYfFMAn",
              ["dsh-plugin", "agents", "api-keys", "cli", "credentials", "developer-tools", "mcp", "proxy", "python",
               "registry", "secrets"]), "API & MCP"),
    # manual correction Code -> Skills (book PDF -> agent skill)
    (_fixture("virgiliojr94/book-to-skill",
              "Turn any technical book PDF into a Claude Code skill — ready to study, reference, and use while you work.",
              ["agent-skills", "ai-agents", "context-engineering", "document-processing", "edtech", "knowledge-base",
               "knowledge-management", "llm", "pdf-to-markdown", "rag", "self-study", "study-tools", "book-to-skill"]), "Skills"),
    # cross-domain plugin marketplace -> Skills (like anthropics/skills)
    (_fixture("anthropics/claude-plugins-official",
              "Official, Anthropic-managed directory of high quality Claude Code Plugins.",
              ["claude-code", "mcp", "skills"]), "Skills"),
    # manual correction Security -> Router (fake AI relay detector, like canarybyte/veridrop)
    (_fixture("mintesnot-teshome/llm-verify",
              "Detect fake AI APIs — Verify if an LLM API is actually serving the model it claims. Catch resellers selling "
              "\"Claude\" or \"ChatGPT\" that secretly serve cheaper models. Behavioral fingerprinting with 32 forensic prompts.",
              ["ai", "ai-safety", "anthropic", "api-testing", "benchmark", "chatgpt", "claude", "fastapi",
               "fingerprinting", "fraud-detection", "llm", "llm-evaluation", "model-verification", "openai", "python"]), "Router"),
    # 25 Oct 2026: was Video & Images ("photos", "videos" in the file-type list);
    # reviewed: local file search utility -> Productivity, like the Wox launcher
    (_fixture("ARahim3/DigUp",
              "Search your computer by what's in your files: photos, PDFs, documents, recordings, videos and code. "
              "On-device on Mac, Windows and Linux, built on Google DeepMind's EmbeddingGemma 2.",
              ["embeddinggemma", "embeddings", "file-search", "linux", "llama-cpp", "local-first", "macos",
               "menubar-app", "multimodal", "on-device", "semantic-search", "swift", "tauri", "windows"]), "Productivity"),
    # 26 Oct 2026: placed in Memory by hand at star time; classifier already said Router.
    # Owner-approved Router: LLM gateway/proxy (one OpenAI-compatible API over hosted/BYOK/local models,
    # per-user quota and cost control, traffic-driven routing) - no memory/recall/RAG function. Pins the
    # Router verdict so a later Memory/RAG pattern cannot reclaim this description.
    (_fixture("experientiallabs/experiential",
              "Experiential is the open source, zero markup gateway for BYOK, self-hosted and 1000+ marketplace "
              "models. It learns from your traffic to cut costs, recommend better models, and train a specialized "
              "model you own."), "Router"),
]

def _test_render_catalog():
    """Catalog format: header, case-insensitive sort, archived marker, empty section, whitespace collapse."""
    lists = {
        "api & MCP": {"description": "Registry.", "items": [
            {"id": "R2", "nameWithOwner": "zeta/b", "url": "https://github.com/zeta/b", "description": None, "isArchived": False},
            {"id": "R1", "nameWithOwner": "Alpha/a", "url": "https://github.com/Alpha/a",
             "description": "  Two\n  spaces  ", "isArchived": True},
        ]},
        "Agent": {"description": "General agents.", "items": [
            {"id": "R3", "nameWithOwner": "beta/c", "url": "https://github.com/beta/c", "description": "Desc", "isArchived": False},
        ]},
        "Others": {"description": "Ambiguous.", "items": []},
    }
    expected = "\n".join([
        "# GitHub Stars Catalog",
        "",
        "> **Account:** acct | **Total Repos:** 3 (5 Starred) | **Lists:** 3",
        "> **Generated:** 19 October 2026 | **Source:** gh_stars_lists.py --export-catalog (live GraphQL snapshot)",
        "",
        "Starred repositories of acct, grouped into 3 GitHub Lists. "
        "Repos marked *(archived)* are no longer maintained by their owners.",
        "",
        "---",
        "",
        "## Agent (1)",
        "*General agents.*",
        "",
        "- [beta/c](https://github.com/beta/c) — Desc",
        "",
        "## api & MCP (2)",
        "*Registry.*",
        "",
        "- [Alpha/a](https://github.com/Alpha/a) — Two spaces *(archived)*",
        "- [zeta/b](https://github.com/zeta/b)",
        "",
        "## Others (0)",
        "*Ambiguous.*",
        "",
        EMPTY_SECTION,
    ]) + "\n"
    actual = render_catalog("acct", lists, 5, datetime.date(2026, 10, 19))
    if actual != expected:
        return [f"render_catalog mismatch:\n--- expected\n{expected}--- actual\n{actual}"]
    return []

def _test_resolve_manifest():
    """Manifest validation runs before any mutation and rejects stale or unreviewed manifests."""
    lists = {"Router": {"id": "L_router"}, "Security": {"id": "L_sec"}, "Others": {"id": "L_oth"}}
    failures = []

    def rejects(manifest, needle, label):
        try:
            resolve_manifest(manifest, lists)
            failures.append(f"resolve_manifest accepted {label}")
        except ValueError as e:
            if needle not in str(e):
                failures.append(f"resolve_manifest {label}: expected '{needle}' in error, got: {e}")

    op_unlisted = {"repo": "a/x", "repo_id": "R1", "from": None, "to": "Router", "to_list_id": "L_router"}
    op_move = {"repo": "b/y", "repo_id": "R2", "from": "Security", "from_list_id": "L_sec", "to": "Router"}
    rejects({"review": "PENDING", "ops": [op_unlisted]}, "PENDING", "an unreviewed plan")
    # Fail closed: a manifest without an explicit approval (e.g. a hand-made one) must not run
    rejects({"ops": [op_unlisted]}, "APPROVED", "a manifest without a review field")
    rejects({"review": "approved-ish", "ops": [op_unlisted]}, "APPROVED", "an unknown review value")
    rejects({"ops": [dict(op_unlisted, to="Others")]}, "to_list_id", "a 'to' edited without its to_list_id")
    rejects({"ops": [op_unlisted, dict(op_unlisted)]}, "duplicate", "a duplicate repo_id")
    rejects({"ops": [dict(op_unlisted, to="Nope", to_list_id=None)]}, "does not exist", "an unknown list")
    rejects({"ops": [dict(op_unlisted, to=None, to_list_id=None)]}, "exactly 1 list", "a missing target")

    ops = resolve_manifest({"review": "APPROVED", "ops": [op_unlisted, op_move]}, lists)
    if [(o['expected_before'], o['target']) for o in ops] != [([], ["L_router"]), (["L_sec"], ["L_router"])]:
        failures.append(f"resolve_manifest forward ops wrong: {ops}")
    back = resolve_manifest({"review": "APPROVED", "ops": [op_unlisted, op_move]}, lists, rollback=True)
    if [(o['repo'], o['expected_before'], o['target']) for o in back] != [("b/y", ["L_router"], ["L_sec"]),
                                                                          ("a/x", ["L_router"], [])]:
        failures.append(f"resolve_manifest rollback ops wrong: {back}")
    return failures

# Real misclassifications found by the 7 Nov 2026 triage: web graphics libraries,
# films made in code, account rotation, webchat shims. Each one passes after the 7 Nov pattern changes.
REGRESSION_2026_11_07 = [
    (_fixture('hex2f/gash', 'A fast, native, bash-compatible shell for Windows: a from-scratch drop-in replacement for Git Bash, written in Rust', []), 'Code'),
    (_fixture('pixijs/pixijs', 'The HTML5 Creation Engine: Create beautiful digital content with the fastest, most flexible 2D WebGL renderer.', ['canvas', 'canvas2d', 'data-visualization', 'game', 'glsl', 'javascript', 'pixi', 'pixijs', 'renderer', 'rendering', 'rendering-2d-graphics', 'rendering-engine', 'webgl']), 'Design'),
    (_fixture('processing/p5.js', 'p5.js is a client-side JS platform that empowers artists, designers, students, and anyone to learn to code and express themselves creatively on the web. It is based on the core principles of Processing. Looking for p5.js 2.0? http://beta.p5js.org', ['art', 'creative-coding', 'design', 'education', 'graphics', 'html', 'javascript', 'learning', 'p5js', 'processing', 'sound']), 'Design'),
    (_fixture('gl-transitions/gl-transitions', 'The open collection of GL Transitions', ['glsl', 'transition', 'transitions', 'webgl']), 'Video & Images'),
    (_fixture('donmccurdy/glTF-Transform', 'glTF 2.0 SDK for JavaScript and TypeScript, on Web and Node.js.', ['3d', 'compression', 'glb', 'gltf', 'mesh-processing', 'optimization', 'scene-graph']), 'Design'),
    (_fixture('oframe/ogl', 'Minimal WebGL Library', []), 'Design'),
    (_fixture('dimforge/rapier', '2D and 3D physics engines focused on performance.', []), 'Design'),
    (_fixture('mrdoob/three.js', 'JavaScript 3D Library.', ['3d', 'augmented-reality', 'canvas', 'html5', 'javascript', 'svg', 'virtual-reality', 'webaudio', 'webgl', 'webgl2', 'webgpu', 'webxr']), 'Design'),
    (_fixture('liabru/matter-js', 'a 2D rigid body physics engine for the web ▲● ■', ['canvas', 'javascript', 'physics', 'physics-engine', 'rigid-bodies', 'web']), 'Design'),
    (_fixture('lemomo-ai/lemo-opuscar', 'A toolbox of film styles made in code for Claude Code: 66 ready to use, and your own. Each style is a style prompt plus a demo film made entirely in code by Claude Opus 5.5, with no video model. By Lemomo. · 一套用代码做片的风格工具箱：66 种现成风格，也能做出你自己的', ['agent-skills', 'ai-agents', 'ai-short-film', 'ai-video', 'animation', 'canvas', 'claude', 'claude-code', 'claude-code-plugin', 'claude-code-skill', 'creative-coding', 'ffmpeg', 'filmmaking', 'motion-graphics', 'opus-5-5', 'prompt-library', 'text-to-speech', 'threejs', 'video-production', 'webgl']), 'Video & Images'),
    (_fixture('JohnHeibel/ClaudeAnimationBase', 'A starter kit for animating hand-painted cartoons with Claude: p5.js + p5.brush, the Clawd character, 31 acted emotions and a guide for the model', []), 'Video & Images'),
    (_fixture('nicceasy/3d-product', 'Skill for creating beautiful product renders.', []), 'Video & Images'),
    (_fixture('amosgyamfi/SwiftUI-Agent-Thinking-Text-Animations', 'Learn to animate nearly all SwiftUI properties. Copy/paste pure SwiftUI motion effects for your projects and apps.', ['animation', 'claude', 'ios', 'motion', 'motion-effect', 'opus', 'swift', 'swiftui-animations', 'swiftui-effects', 'text-animation', 'text-animations', 'text-effects']), 'Design'),
    (_fixture('makevoid/motion-graphics-music-video-skill', 'Opus 5.5 plugin for creating high quality motion graphics videos from just a music track and a prompt', []), 'Video & Images'),
    (_fixture('cth9191/animate', 'Procedural animation in any style for Claude Code: short single-file canvas videos with story, look and storyboard check-ins. 7 built-in styles or one matched from your references, your own music (beat-mapped), real product screenshots, every format from one piece.', ['animation', 'canvas', 'claude-code', 'claude-code-plugin', 'claude-code-skill', 'explainer-video', 'generative-art', 'motion-graphics', 'procedural-animation', 'storyboard']), 'Video & Images'),
    (_fixture('brainstormity/LightPost', 'A lightweight system to automate posting to all of your socials from one dashboard', []), 'Socmed'),
    (_fixture('realiti4/claude-swap', 'Switch between multiple Claude Code accounts, with automatic rate-limit rotation, usage dashboard, and parallel sessions', ['account-manager', 'account-switcher', 'anthropic', 'claude', 'claude-code', 'cli', 'multi-account', 'tui']), 'Router'),
    (_fixture('Tejashmakwana/motionmaxxing', 'Looksmaxxing for motion graphics. An agent skill that turns AI slop videos into films that look made by a motion designer.', ['agent-skills', 'ai', 'claude-code', 'gsap', 'hyperframes', 'motion-graphics', 'motionmaxxing', 'video']), 'Video & Images'),
    (_fixture('paper-design/shaders', 'Zero-dependency canvas shaders that can be installed from npm or designed in Paper', ['react', 'shaders', 'webgl']), 'Design'),
    (_fixture('duclm1x1/Muse-Chat-MCP', 'MCP server + OpenAI-compatible shim to use Meta Muse (muse.ai, Hatch) by driving the real logged-in Chrome.', []), 'Router'),
    (_fixture('multica-ai/andrej-karpathy-skills', "A single CLAUDE.md file to improve Claude Code behavior, derived from Andrej Karpathy's observations on LLM coding pitfalls.", []), 'Code'),
    (_fixture('alchaincyf/huashu-motion', '让你的agent一键直出商业级产品宣传片：会作曲，能指着画面改。Commercial-grade launch films by your coding agent — point at the frame to change it.', ['agent-skills', 'animation', 'claude-code', 'codex', 'gsap', 'launch-video', 'motion-graphics', 'skills']), 'Video & Images'),
    (_fixture('warmbly/warmbly', 'The largest open-source B2B cold outreach and email warmup service.', ['cold-email', 'cold-outreach', 'deliverability', 'email', 'email-marketing', 'email-sender', 'email-warmup', 'marketing', 'marketing-automation', 'sales']), 'Marketing'),
    (_fixture('google/langextract', 'A Python library for extracting structured information from unstructured text using LLMs with precise source grounding and interactive visualization.', ['gemini', 'gemini-ai', 'gemini-api', 'gemini-flash', 'gemini-pro', 'information-extration', 'large-language-models', 'llm', 'nlp', 'python', 'structured-data']), 'Documents'),
]

# Human-reviewed corrections from the 19-21 Nov 2026 runs: classifier
# proposal != final placement. Descriptions/topics fetched live on 21 Nov 2026.
REGRESSION_2026_11_21 = [
    (_fixture('nilbuild/stick-scene', 'Skill to draw stick figure animated visuals', []), 'Video & Images'),  # was Skills
    (_fixture('ultralytics/ultralytics', 'Ultralytics YOLO27, YOLO26, YOLO11, YOLOv8 — object detection, instance segmentation, semantic segmentation, image classification, pose estimation, object tracking', ['ultralytics', 'yolov8', 'yolo', 'deep-learning', 'image-classification', 'machine-learning', 'object-detection', 'pytorch', 'tracking', 'instance-segmentation', 'yolo11', 'computer-vision', 'python', 'pose-estimation', 'rotated-object-detection', 'segment-anything', 'yolo26', 'object-tracking', 'semantic-segmentation', 'yolo27']), 'AI Models'),  # was Video & Images
    (_fixture('XBuilderLAB/cheat-on-content', "You're reading this. The skill predicted it. A workflow that turns every post into a calibrated experiment—score, blind-predict, retro, evolve. The future doesn't reward effort, it rewards those who see the pattern first. 1M followers in a month — not luck, system.", []), 'Socmed'),  # was Skills
    (_fixture('HackerNews/API', 'Documentation and Samples for the Official HN API', []), 'Socmed'),  # was API & MCP
    (_fixture('raycast/ray-so', 'Create code snippets, browse AI prompts, create extension icons and more.', []), 'Design'),  # was Prompts
    (_fixture('FxEmbed/FxEmbed', 'Fix X/Twitter and Bluesky embeds! Use multiple images, videos, polls, translations and more on Discord, Telegram and others', []), 'Socmed'),  # was Others
    (_fixture('xdevplatform/xurl', 'The official CLI for the X API', []), 'Socmed'),  # was API & MCP
    (_fixture('greensock/gsap-skills', 'Official AI skills for GSAP. These skills teach AI coding agents how to correctly use GSAP (GreenSock Animation Platform), including best practices, common animation patterns, and plugin usage.', []), 'Design'),  # was Code
    (_fixture('ahujasid/mcp-for-blender', 'Community plugin to control Blender 3D with any LLM of your choice. Not affiliated with the official Blender Foundation.', ['3d-modeling', 'ai', 'blender', 'blender-addon', 'claude', 'generative-ai', 'llm', 'mcp', 'model-context-protocol', 'python', 'blender-mcp']), 'Design'),  # was API & MCP
    (_fixture('arjun988/blender-skills', '94 specialist Blender skills for Cursor, Claude Code, Kiro & Codex -> MCP-powered production pipeline from blockout to engine export.', ['3d-models', 'agent', 'agent-skills', 'blender', 'blender-addon', 'blender-mcp', 'claude-code', 'claude-skills', 'cursor-ai', 'game-development', 'mcp']), 'Design'),  # was Skills
    (_fixture('majidmanzarpour/threejs-game-skills', 'Agent skills for building playable, polished Three.js browser games with gameplay, AAA-style graphics, UI, QA, and optional AI-generated 3D, image, and audio assets.', []), 'Design'),  # was Video & Images
    (_fixture('duwqijlk/muse-protocol', 'muse.ai 注册与邀请码兑换协议研究（纯 HTTP Python 实现）', []), 'Router'),  # was Others
    (_fixture('achimala/dream-loop', 'Agent skill for impressive 3D visuals using Blender + image gen + subagent critic', []), 'Design'),  # was Video & Images
    (_fixture('MengTo/Skills', 'Agent skills for designers and builders using Codex, Claude, Cursor, and other AI coding agents', []), 'Design'),  # was Code
    (_fixture('microsoft/postgres-mcp', '', []), 'Cloud & Storage'),  # was API & MCP
    (_fixture('sandwich0071/v380-dual-lens-rtsp-onvif', 'Panduan mengaktifkan RTSP dan ONVIF lokal di kamera V380 dual-lens untuk NVR apa pun.', ['cctv', 'dual-lens', 'frigate', 'home-assistant', 'ip-camera', 'local-recording', 'nvr', 'onvif', 'rtsp', 'v380']), 'Video & Images'),  # was Others
    (_fixture('open-free-llm-api/awesome-freellm-apis', '134+ free LLM APIs & AI API keys from 40+ providers. Google Gemini, NVIDIA NIM, Groq, OpenRouter & more. One-click setup for Claude Code, Cursor and Codex.', ['freellm', 'freellmapi', 'free-llm-api', 'free-llm-resources', 'free-models', 'free-llm-models']), 'Router'),  # was API & MCP
    (_fixture('INSANE0777/Awwwards-mcp', 'Free, open-source MCP server that gives AI coding agents (Claude Code, Codex, Cursor, OpenCode, ZCode…) design inspiration from award-winning websites — search with real screenshots, pull design DNA, capture and record live sites. A Mobbin alternative. No API key.', ['ai-agents', 'awwwards', 'claude-code', 'codex', 'coding-agent', 'cursor', 'design-inspiration', 'mcp', 'mcp-server', 'opencode', 'web-design']), 'Design'),  # was Code
    (_fixture('localsend/localsend', 'An open-source cross-platform alternative to AirDrop', ['flutter', 'file-sharing', 'dart', 'flutter-apps']), 'Cloud & Storage'),  # was Others
    (_fixture('thisuxhq/dukoi', 'Deploy real apps to old Android phones. One command. No root, no Termux, no cloud bill.', ['android', 'cli', 'cloudflare-tunnel', 'deployment', 'nodejs', 'self-hosting']), 'Infra'),  # was Others
    (_fixture('Rapptz/discord.py', 'An API wrapper for Discord written in Python.', ['discord', 'discord-api', 'python', 'python-3', 'bot', 'discord-bot', 'discord-py']), 'Socmed'),  # was API & MCP
    (_fixture('dolfies/discord.py-self', 'A fork of the popular discord.py for user accounts', ['discord', 'selfbot', 'discord-py', 'discord-bot', 'discordbot', 'hacktoberfest']), 'Socmed'),  # was Others
    (_fixture('Tyrrrz/DiscordChatExporter', 'Saves Discord chat logs to a file', ['discord', 'chat', 'log', 'export', 'archival', 'archiver', 'expoter']), 'Cloud & Storage'),  # was Others
    (_fixture('TubeLabHQ/youtube-research-skills', 'AI agent skills for YouTube research. Outlier videos, niche finding & validation, competitor research, comment mining, title formulas, thumbnail concepts, script breakdowns, monetization gaps & sponsor prospecting. Powered by TubeLab. Works with Claude Code, Cursor, Codex, ChatGPT, Grok.', ['agent-skills', 'ai-agents', 'claude-code', 'claude-skills', 'codex', 'codex-skill', 'competitor-analysis', 'content-marketing', 'market-research', 'workflow-automation', 'youtube', 'youtube-research', 'youtube-research-automation', 'youtube-strategy']), 'Socmed'),  # was Others
    (_fixture('storytold/craft-anything', 'Craft Anything: understand how any software works, and craft your own.', []), 'Security'),  # was Others
    (_fixture('The-Cool-Coders/Project-Ideas-And-Resources', 'A Collection of application ideas that can be used to improve your coding skills ❤.', ['projects', 'react', 'javascript', 'html', 'css', 'frontend', 'open-source', 'python', 'php', 'beginner', 'contribution', 'contributions-welcome', 'opensource', 'hacktoberfest']), 'Code'),  # was Design
    (_fixture('luobinger/PerkRadar', 'PerkRadar — A self-hosted deals aggregator that fetches freebies, limited-time offers, and discounts from multiple sources every two hours, with source status tracking, expiration handling, and personal bookmarks.', []), 'Productivity'),  # was Others
    (_fixture('Subhan-code/Amicro--Micro-transitions-', '', []), 'Design'),  # was Others
    (_fixture('shadcn/improve', 'Use your most capable model to audit your codebase and write plans for cheaper models to execute.', []), 'Code'),  # was Design
    (_fixture('ln-dev7/landing-pages', 'Open-source landing pages with a personality of their own.', []), 'Design'),  # was Others
    (_fixture('MatiSolina/busy', 'Your own team of AI bots, each with memory, tools, and its own computer.', []), 'Agent'),  # was Memory
    (_fixture('erennyuksell/ag-multi-account-switchboard', 'Switch between Antigravity accounts instantly. Monitor AI quotas, token budgets and reset timers.', []), 'Router'),  # was Others
    (_fixture('monid-ai/monid', 'Monid - OpenRouter for agent tools. Join our community at https://discord.gg/rQzztcgJV8', ['ai-agents', 'developer-tools']), 'API & MCP'),  # was Agent
    (_fixture('rustdesk/rustdesk', 'An open-source remote desktop application designed for self-hosting, as an alternative to TeamViewer.', ['remote-control', 'remote-desktop', 'teamviewer', 'anydesk', 'vnc', 'rdp', 'rust', 'p2p', 'flutter', 'flutter-apps', 'dart', 'rust-lang', 'wayland', 'linux', 'android', 'flatpak', 'ios', 'macos', 'windows']), 'Infra'),  # was Mobile
    (_fixture('bitwarden/agent-access', 'Agent Access is an open protocol, CLI tool, and SDK to provide agents with credentials without exposing their entire vault', []), 'Security'),  # was API & MCP
]

def run_tests():
    """Unit tests: classifier rules (auditor probes + 19 Oct regressions), catalog renderer, manifest validation."""
    test_cases = [
        # Auditor probe 1: moneylover-mcp -> Finance (not API & MCP)
        ({"nameWithOwner": "user/moneylover-mcp", "description": "Moneylover personal finance tracking via MCP"}, "Finance"),
        # Auditor probe 2: pdf-mcp -> Documents (not API & MCP)
        ({"nameWithOwner": "user/pdf-mcp", "description": "Fast PDF parsing and extraction MCP server"}, "Documents"),
        # Auditor probe 3: crypto trading Solana -> Crypto (not Stocks)
        ({"nameWithOwner": "user/solana-trading-bot", "description": "Automated crypto trading bot on Solana DEX"}, "Crypto"),
        # Stocks without crypto -> Stocks
        ({"nameWithOwner": "user/idx-screener", "description": "Stock screener for Indonesia IDX stock market"}, "Stocks"),
        # Generic MCP registry with no specific domain -> API & MCP
        ({"nameWithOwner": "modelcontextprotocol/servers", "description": "Model Context Protocol reference servers"}, "API & MCP"),
        # Generic skills framework -> Skills
        ({"nameWithOwner": "someone/skills", "description": "Agent skills framework"}, "Skills"),
        # Generic prompt library -> Prompts
        ({"nameWithOwner": "f/awesome-chatgpt-prompts", "description": "ChatGPT prompts collection"}, "Prompts"),
        # Ambiguous multiple conflicting domains -> Others
        ({"nameWithOwner": "user/random-mix", "description": "A random mix of music audio and medical research paper"}, "Others"),
    ] + REGRESSION_2026_10_19 + REGRESSION_2026_11_07 + REGRESSION_2026_11_21
    failures = []
    for repo, expected in test_cases:
        actual, reason = classify_detail(repo)
        if actual != expected:
            failures.append(f"{repo['nameWithOwner']}: expected {expected}, got {actual} ({reason})")
    classifier_failures = len(failures)
    failures += _test_render_catalog()
    failures += _test_resolve_manifest()
    for stderr, expected in [("gh: unexpected end of JSON input", True), ("HTTP 502 Bad Gateway", True),
                             ("unexpected EOF", True), ("HTTP 401: Bad credentials", False),
                             ("GraphQL: Could not resolve to a node", False), ("", False)]:
        if is_transient_gh_error(stderr) != expected:
            failures.append(f"is_transient_gh_error({stderr!r}) should be {expected}")
    if failures:
        print(f"[X] {len(failures)} test(s) FAILED ({classifier_failures} of {len(test_cases)} classifier cases):")
        for f in failures:
            print(f"    - {f}")
        return False
    n_reg = len(REGRESSION_2026_10_19) + len(REGRESSION_2026_11_07) + len(REGRESSION_2026_11_21)
    print(f"[+] All {len(test_cases)} classifier cases PASS "
          f"({len(test_cases) - n_reg} auditor probes + {n_reg} real-world regression cases).")
    print("[+] Catalog renderer and manifest validation tests PASS.")
    return True

def run_audit(limit, full):
    """Read-only audit: unlisted, multi-list and (full mode) listed-but-not-starred repos, with suggestions.

    Returns 0 when the examined stars are compliant, 1 otherwise.
    """
    mode_label = "FULL ACCOUNT AUDIT" if full else f"RECENT {limit} STARS"
    print(f"[*] Starting gh_stars_lists in [{mode_label}] mode (read-only)...")

    # Step 1: Preflight Account Validation
    viewer_login, lists = get_live_lists_paginated()
    require_account(viewer_login)
    print(f"[+] Authenticated viewer: {viewer_login} (Verified)")
    print(f"[+] Loaded {len(lists)} active user lists (with complete paginated members).")

    # Step 2: Build membership lookup: repo_id -> set of list_names
    repo_to_lists = {}
    total_memberships = 0
    for lname, ldata in lists.items():
        total_memberships += len(ldata['members'])
        for rid in ldata['members']:
            repo_to_lists.setdefault(rid, set()).add(lname)
    print(f"[+] Total list memberships across all lists: {total_memberships}")

    # Step 3: Fetch Stars (paginated)
    _, total_stars, stars_edges = get_stars_paginated(limit=limit, audit=full)
    print(f"[+] Total stars on account: {total_stars} (examined: {len(stars_edges)})")

    # Step 4: Detect Unlisted, Multi-List and (full audit only) listed-but-not-starred
    unlisted = [e['node'] for e in stars_edges if not repo_to_lists.get(e['node']['id'])]
    multi_list = [(e['node'], repo_to_lists[e['node']['id']]) for e in stars_edges
                  if len(repo_to_lists.get(e['node']['id'], ())) > 1]
    not_starred = []
    if full:
        starred_ids = {e['node']['id'] for e in stars_edges}
        names = {rid: nwo for l in lists.values() for rid, nwo in l['members'].items()}
        not_starred = sorted(names[rid] for rid in repo_to_lists if rid not in starred_ids)

    print("-" * 65)
    if multi_list:
        print(f"[!] Warning: Found {len(multi_list)} repositories in MULTIPLE lists:")
        for node, assigned in multi_list:
            print(f"    - {node['nameWithOwner']} -> {sorted(assigned)}")
    else:
        print("[+] Zero multi-list duplicates found.")
    if full:
        if not_starred:
            print(f"[!] Warning: Found {len(not_starred)} list members that are NOT starred:")
            for nwo in not_starred:
                print(f"    - {nwo}")
        else:
            print("[+] Zero list members without a star.")

    if unlisted:
        print(f"\n[!] Found {len(unlisted)} UNLISTED repositories (classifier proposals, not applied):")
        for node in unlisted:
            target, reason = classify_detail(node)
            print(f"    - {node['nameWithOwner']}: '{node.get('description') or 'No description'}'")
            print(f"      ==> Proposal: [{target}] — {reason}")
        print("\n[i] Build a manifest to review: python gh_stars_lists.py --plan runs/<date>/manifest.json")
    else:
        print(f"[+] All {len(stars_edges)} examined starred repositories are assigned to a list! (0 unlisted)")

    if not unlisted and not multi_list and not not_starred:
        print("[+] PASS: Account integrity is 100% compliant.")
        return 0
    print("[X] NOT COMPLIANT: see the findings above.")
    return 1

def run_plan(path):
    if os.path.exists(path):
        print(f"[X] {path} already exists. Pick another file name so a reviewed manifest is never overwritten.")
        return 2
    print("[*] Building review manifest from a FULL ACCOUNT scan (read-only)...")
    viewer_login, lists = get_live_lists_paginated()
    require_account(viewer_login)
    _, total_stars, stars_edges = get_stars_paginated(audit=True)
    plan = build_plan(viewer_login, lists, total_stars, stars_edges)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(plan, f, ensure_ascii=False, indent=1)
        f.write("\n")
    b = plan['baseline']
    print(f"[+] Baseline: {b['stars']} stars, {b['lists']} lists, {b['listed']} listed, "
          f"{b['unlisted']} unlisted, {b['multi_list']} multi-list")
    for op in plan['ops']:
        print(f"    - [{op['group']}] {op['repo']} -> {op['to']} | {op['reason']}")
    print(f"[+] Manifest written: {path} ({len(plan['ops'])} ops, review: PENDING)")
    if plan['ops']:
        print("[i] Review the manifest, set \"review\": \"APPROVED\", then run --apply-manifest (dry-run first).")
    return 0

def main():
    # UTF-8 for emoji in descriptions; newline='\n' so a redirected --export-catalog stays LF like the catalog.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace', newline='\n')
        except AttributeError:
            pass
    parser = argparse.ArgumentParser(
        description="Keep every GitHub star in exactly one GitHub List (a classifier proposes, a reviewer decides).")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--test", action="store_true", help="Run classifier, catalog renderer and manifest unit tests (offline)")
    action.add_argument("--plan", metavar="FILE.json",
                        help="Full read-only scan; write a review manifest for unlisted/multi-list stars (review: PENDING)")
    action.add_argument("--apply-manifest", metavar="FILE.json",
                        help="Run a reviewed manifest serially with live state checks; dry-run unless --confirm")
    action.add_argument("--export-catalog", nargs="?", const="-", metavar="PATH",
                        help="Render a Markdown catalog of your lists to stdout (default) or PATH")
    action.add_argument("--taxonomy", action="store_true", help="Print the list names the classifier can propose")
    parser.add_argument("--confirm", action="store_true", help="With --apply-manifest: actually run the mutations")
    parser.add_argument("--rollback", action="store_true", help="With --apply-manifest: undo it (from <-> to, reverse order)")
    parser.add_argument("--journal", metavar="FILE.jsonl",
                        help="With --apply-manifest --confirm: JSONL journal path (default: <manifest>-journal.jsonl)")
    parser.add_argument("--limit", type=int, default=30, help="Audit: check N most recent stars (default 30)")
    parser.add_argument("--audit", action="store_true", help="Audit all stars across the entire account")
    parser.add_argument("--account", metavar="LOGIN", help="Refuse to run unless `gh` is logged in as LOGIN")
    args = parser.parse_args()
    global TARGET_ACCOUNT
    TARGET_ACCOUNT = args.account

    if (args.confirm or args.rollback or args.journal) and not args.apply_manifest:
        parser.error("--confirm, --rollback and --journal only work with --apply-manifest")
    if args.taxonomy:
        for name in taxonomy():
            print(name)
        return
    if args.test:
        sys.exit(0 if run_tests() else 1)
    if args.export_catalog:
        export_catalog(args.export_catalog)
        return
    if args.plan:
        sys.exit(run_plan(args.plan))
    if args.apply_manifest:
        sys.exit(apply_manifest(args.apply_manifest, confirm=args.confirm, rollback=args.rollback,
                                journal_path=args.journal))
    sys.exit(run_audit(args.limit, args.audit))

if __name__ == '__main__':
    main()
