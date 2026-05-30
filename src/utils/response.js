// src/utils/response.js
const success = (res, data, message = 'Request successful', statusCode = 200, meta = null) => {
  const body = { success: true, message, data };
  if (meta) body.meta = meta;
  return res.status(statusCode).json(body);
};

const error = (res, statusCode, code, message, details = null) => {
  const body = { success: false, error: { code, message } };
  if (details) body.error.details = details;
  return res.status(statusCode).json(body);
};

const paginate = (totalItems, page, limit) => ({
  totalItems,
  totalPages: Math.ceil(totalItems / limit),
  currentPage: page,
  itemsPerPage: limit,
  hasNextPage:      page < Math.ceil(totalItems / limit),
  hasPreviousPage:  page > 1,
});

module.exports = { success, error, paginate };