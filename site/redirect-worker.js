// wishpkgs.com (+ www) -> lib.wishpkgs.org, preserving path/query.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const target = new URL(url.pathname + url.search, "https://lib.wishpkgs.org");
    return Response.redirect(target.toString(), 301);
  },
};
