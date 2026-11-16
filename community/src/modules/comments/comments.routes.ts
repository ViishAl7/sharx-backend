
import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";

import { getPrisma } from "../../lib/database.js";
import { requireAuth } from "../../lib/require-auth.js";

const uuidSchema = z.string().uuid();

const commentSchema = z.object({
  content: z.string().trim().min(1).max(2200)
});

async function canAccessPost(postId: string, userId?: string) {
  const prisma = getPrisma();

  const post = await prisma.post.findFirst({
    where: {
      id: postId,
      status: "PUBLISHED",
      OR: [
        { visibility: "PUBLIC" },
        ...(userId
          ? [
              { authorId: userId },
              {
                visibility: "FOLLOWERS" as const,
                author: {
                  followers: {
                    some: { followerId: userId }
                  }
                }
              }
            ]
          : [])
      ]
    },
    select: { id: true }
  });

  return Boolean(post);
}

const commentsRoutes: FastifyPluginAsync = async (app) => {
  // GET COMMENTS
  app.get("/:postId/comments", async (request, reply) => {
    const params = z.object({
      postId: uuidSchema
    }).safeParse(request.params);

    if (!params.success) {
      return reply.code(400).send({ error: "Invalid post ID" });
    }

    const prisma = getPrisma();

    const authorization = request.headers.authorization;
    let userId: string | undefined;

    if (authorization?.startsWith("Bearer ")) {
      const auth = await requireAuth(request, reply);

      if (!auth) return;
      userId = auth.id;
    }

    try {
      const accessible = await canAccessPost(
        params.data.postId,
        userId
      );

      if (!accessible) {
        return reply.code(404).send({ error: "Post not found" });
      }

      const comments = await prisma.comment.findMany({
        where: {
          postId: params.data.postId,
          parentId: null
        },
        orderBy: { createdAt: "desc" },
        take: 50,
        include: {
          user: {
            select: {
              id: true,
              username: true
            }
          },
          replies: {
            orderBy: { createdAt: "asc" },
            take: 50,
            include: {
              user: {
                select: {
                  id: true,
                  username: true
                }
              },
              _count: {
                select: { replies: true }
              }
            }
          },
          _count: {
            select: { replies: true }
          }
        }
      });

      const total = await prisma.comment.count({
        where: { postId: params.data.postId }
      });

      return reply.send({
        comments,
        total
      });
    } catch (error) {
      request.log.error(error);
      return reply.code(500).send({
        error: "Unable to fetch comments"
      });
    }
  });

  // ADD COMMENT
  app.post("/:postId/comments", async (request, reply) => {
    const auth = await requireAuth(request, reply);
    if (!auth) return;

    const params = z.object({
      postId: uuidSchema
    }).safeParse(request.params);

    const body = commentSchema.safeParse(request.body);

    if (!params.success || !body.success) {
      return reply.code(400).send({
        error: "Invalid post ID or comment content"
      });
    }

    try {
      const prisma = getPrisma();

      const accessible = await canAccessPost(
        params.data.postId,
        auth.id
      );

      if (!accessible) {
        return reply.code(404).send({ error: "Post not found" });
      }

      const comment = await prisma.comment.create({
        data: {
          postId: params.data.postId,
          userId: auth.id,
          content: body.data.content
        },
        include: {
          user: {
            select: {
              id: true,
              username: true
            }
          }
        }
      });

      return reply.code(201).send({
        message: "Comment added successfully",
        comment
      });
    } catch (error) {
      request.log.error(error);
      return reply.code(500).send({
        error: "Unable to add comment"
      });
    }
  });

  // REPLY TO COMMENT
  app.post(
    "/:postId/comments/:commentId/replies",
    async (request, reply) => {
      const auth = await requireAuth(request, reply);
      if (!auth) return;

      const params = z.object({
        postId: uuidSchema,
        commentId: uuidSchema
      }).safeParse(request.params);

      const body = commentSchema.safeParse(request.body);

      if (!params.success || !body.success) {
        return reply.code(400).send({
          error: "Invalid request data"
        });
      }

      try {
        const prisma = getPrisma();

        const accessible = await canAccessPost(
          params.data.postId,
          auth.id
        );

        if (!accessible) {
          return reply.code(404).send({ error: "Post not found" });
        }

        const parent = await prisma.comment.findFirst({
          where: {
            id: params.data.commentId,
            postId: params.data.postId
          },
          select: { id: true }
        });

        if (!parent) {
          return reply.code(404).send({
            error: "Parent comment not found"
          });
        }

        const replyComment = await prisma.comment.create({
          data: {
            postId: params.data.postId,
            userId: auth.id,
            parentId: parent.id,
            content: body.data.content
          },
          include: {
            user: {
              select: {
                id: true,
                username: true
              }
            }
          }
        });

        return reply.code(201).send({
          message: "Reply added successfully",
          reply: replyComment
        });
      } catch (error) {
        request.log.error(error);
        return reply.code(500).send({
          error: "Unable to add reply"
        });
      }
    }
  );

  // DELETE COMMENT OR REPLY
  app.delete(
    "/:postId/comments/:commentId",
    async (request, reply) => {
      const auth = await requireAuth(request, reply);
      if (!auth) return;

      const params = z.object({
        postId: uuidSchema,
        commentId: uuidSchema
      }).safeParse(request.params);

      if (!params.success) {
        return reply.code(400).send({
          error: "Invalid request parameters"
        });
      }

      try {
        const prisma = getPrisma();

        const comment = await prisma.comment.findFirst({
          where: {
            id: params.data.commentId,
            postId: params.data.postId
          },
          select: {
            id: true,
            userId: true
          }
        });

        if (!comment) {
          return reply.code(404).send({
            error: "Comment not found"
          });
        }

        if (comment.userId !== auth.id) {
          return reply.code(403).send({
            error: "You can only delete your own comments"
          });
        }

        await prisma.comment.delete({
          where: { id: comment.id }
        });

        return reply.send({
          message: "Comment deleted successfully"
        });
      } catch (error) {
        request.log.error(error);
        return reply.code(500).send({
          error: "Unable to delete comment"
        });
      }
    }
  );
};

export default commentsRoutes;
