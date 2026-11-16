
import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";

import { getPrisma } from "../../lib/database.js";
import { requireAuth } from "../../lib/require-auth.js";
import { verifyAccessToken } from "../auth/auth.jwt.js";

const createPostSchema = z.object({
  caption: z.string().trim().min(1).max(2200),
  visibility: z.enum(["PUBLIC", "FOLLOWERS", "PRIVATE"]).default("PUBLIC")
});

const postIdSchema = z.string().uuid();

const postsRoutes: FastifyPluginAsync = async (app) => {

  // GET /feed — Public feed with visibility checks
  app.get("/feed", async (request, reply) => {
    const prisma = getPrisma();
    let userId: string | null = null;

    const authorization = request.headers.authorization;

    if (authorization?.startsWith("Bearer ")) {
      try {
        const token = authorization.slice(7).trim();

        if (token && token.length <= 4096) {
          const payload = await verifyAccessToken(token);

          const user = await prisma.communityUser.findFirst({
            where: {
              id: payload.sub,
              status: "ACTIVE",
              emailVerifiedAt: { not: null }
            },
            select: { id: true }
          });

          userId = user?.id ?? null;
        }
      } catch {
        userId = null;
      }
    }

    const posts = await prisma.post.findMany({
      where: {
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
      orderBy: { createdAt: "desc" },
      take: 30,
      select: {
        id: true,
        caption: true,
        visibility: true,
        createdAt: true,
        author: {
          select: {
            id: true,
            username: true,
            profile: {
              select: {
                displayName: true,
                avatarKey: true
              }
            }
          }
        },
        media: {
          orderBy: { position: "asc" },
          select: {
            id: true,
            type: true,
            thumbnailKey: true,
            mimeType: true,
            width: true,
            height: true,
            position: true,
            altText: true
          }
        },
        _count: {
          select: {
            likes: true,
            comments: true
          }
        }
      }
    });

    return reply.send({ posts });
  });

  // POST / — Create a text post
  app.post("/", async (request, reply) => {
    const user = await requireAuth(request, reply);
    if (!user) return;

    const parsed = createPostSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.code(400).send({
        error: "Invalid post data",
        details: parsed.error.flatten().fieldErrors
      });
    }

    try {
      const prisma = getPrisma();

      const post = await prisma.post.create({
        data: {
          authorId: user.id,
          caption: parsed.data.caption,
          visibility: parsed.data.visibility,
          status: "PUBLISHED"
        },
        select: {
          id: true,
          caption: true,
          visibility: true,
          createdAt: true
        }
      });

      return reply.code(201).send({ post });
    } catch (error) {
      request.log.error(error);
      return reply.code(500).send({ error: "Unable to create post" });
    }
  });

  // POST /:postId/like — Like a post
  app.post("/:postId/like", async (request, reply) => {
    const user = await requireAuth(request, reply);
    if (!user) return;

    const parsed = postIdSchema.safeParse(
      (request.params as { postId?: string }).postId
    );

    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid post ID" });
    }

    const prisma = getPrisma();

    try {
      const post = await prisma.post.findFirst({
        where: {
          id: parsed.data,
          status: "PUBLISHED",
          OR: [
            { visibility: "PUBLIC" },
            { authorId: user.id },
            {
              visibility: "FOLLOWERS",
              author: {
                followers: {
                  some: { followerId: user.id }
                }
              }
            }
          ]
        },
        select: { id: true }
      });

      if (!post) {
        return reply.code(404).send({ error: "Post not found" });
      }

      await prisma.like.upsert({
        where: {
          userId_postId: {
            userId: user.id,
            postId: post.id
          }
        },
        create: {
          userId: user.id,
          postId: post.id
        },
        update: {}
      });

      const likeCount = await prisma.like.count({
        where: { postId: post.id }
      });

      return reply.send({
        liked: true,
        likeCount
      });
    } catch (error) {
      request.log.error(error);
      return reply.code(500).send({ error: "Unable to like post" });
    }
  });

  // DELETE /:postId/like — Unlike a post
  app.delete("/:postId/like", async (request, reply) => {
    const user = await requireAuth(request, reply);
    if (!user) return;

    const parsed = postIdSchema.safeParse(
      (request.params as { postId?: string }).postId
    );

    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid post ID" });
    }

    const prisma = getPrisma();

    try {
      const post = await prisma.post.findFirst({
        where: {
          id: parsed.data,
          status: "PUBLISHED",
          OR: [
            { visibility: "PUBLIC" },
            { authorId: user.id },
            {
              visibility: "FOLLOWERS",
              author: {
                followers: {
                  some: { followerId: user.id }
                }
              }
            }
          ]
        },
        select: { id: true }
      });

      if (!post) {
        return reply.code(404).send({ error: "Post not found" });
      }

      await prisma.like.deleteMany({
        where: {
          userId: user.id,
          postId: post.id
        }
      });

      const likeCount = await prisma.like.count({
        where: { postId: post.id }
      });

      return reply.send({
        liked: false,
        likeCount
      });
    } catch (error) {
      request.log.error(error);
      return reply.code(500).send({ error: "Unable to unlike post" });
    }
  });
};

export default postsRoutes;
