export default {
  fetch() {
    return new Response('Not found', {
      status: 404,
      headers: {'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'},
    });
  },
};
