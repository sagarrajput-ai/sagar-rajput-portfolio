Sagar Rajput Portfolio - SEO Foundation Update v1

This update is designed to be applied on top of the already-deployed
Security hardening for Network Engineering Toolkit commit.

Replace/add these files:
- app.py
- templates/base.html
- templates/index.html
- templates/dns_lookup.html
- templates/ip_calculator.html
- templates/ip_range.html
- templates/network_toolkit.html
- templates/network_toolkit_project.html
- templates/port_checker.html
- templates/projects.html
- templates/resume.html
- templates/subnet_planner.html
- static/favicon.svg

Do NOT delete or replace static/css, static/js, images, or the resume PDF.

Main changes:
- Fixed canonical URL to https://sagarrajput.com
- Added page descriptions
- Added Open Graph metadata
- Added Twitter card metadata
- Added Person JSON-LD on the homepage
- Added robots.txt route
- Added sitemap.xml route
- Added favicon
- Added GitHub to footer links
- Preserved the existing visible design/content

Before deployment:
1. Back up the current repository.
2. Apply the files above.
3. Run the site locally.
4. Check /, /robots.txt, /sitemap.xml.
5. Check canonical/OG tags in page source.
6. Then commit and deploy to Render.
