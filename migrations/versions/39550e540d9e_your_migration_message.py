"""Your migration message

Revision ID: 39550e540d9e
Revises: 
Create Date: 2023-10-17 19:21:07.251535

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '39550e540d9e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('ya', sa.String(length=60), nullable=True))
    op.drop_column('user', 'test')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('test', sa.VARCHAR(length=60), nullable=True))
    op.drop_column('user', 'ya')
    # ### end Alembic commands ###
